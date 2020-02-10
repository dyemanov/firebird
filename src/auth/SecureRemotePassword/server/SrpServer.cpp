/*
 *	PROGRAM:		Firebird authentication.
 *	MODULE:			SrpServer.cpp
 *	DESCRIPTION:	SPR authentication plugin.
 *
 *  The contents of this file are subject to the Initial
 *  Developer's Public License Version 1.0 (the "License");
 *  you may not use this file except in compliance with the
 *  License. You may obtain a copy of the License at
 *  http://www.ibphoenix.com/main.nfs?a=ibphoenix&page=ibp_idpl.
 *
 *  Software distributed under the License is distributed AS IS,
 *  WITHOUT WARRANTY OF ANY KIND, either express or implied.
 *  See the License for the specific language governing rights
 *  and limitations under the License.
 *
 *  The Original Code was created by Alex Peshkov
 *  for the Firebird Open Source RDBMS project.
 *
 *  Copyright (c) 2011 Alex Peshkov <peshkoff at mail.ru>
 *  and all contributors signed below.
 *
 *  All Rights Reserved.
 *  Contributor(s): ______________________________________.
 */

#include "firebird.h"
#include "firebird/Message.h"

#include "../auth/SecureRemotePassword/server/SrpServer.h"
#include "../auth/SecureRemotePassword/srp.h"
#include "../common/classes/ImplementHelper.h"
#include "../common/classes/ClumpletWriter.h"
#include "../jrd/status.h"
#include "../common/isc_proto.h"

#include "../jrd/constants.h"
#include "../auth/SecDbCache.h"

using namespace Firebird;
using namespace Auth;

namespace {

GlobalPtr<PluginDatabases> instances;

const unsigned int INIT_KEY = ((~0) - 1);
unsigned int secDbKey = INIT_KEY;

const unsigned int SZ_LOGIN = 31;

struct Metadata
{
	Jrd::FbLocalStatus status;
	FB_MESSAGE (Param, CheckStatusWrapper,
		(FB_VARCHAR(SZ_LOGIN), login)
	) param;
	FB_MESSAGE (Data, CheckStatusWrapper,
		(FB_VARCHAR(128), verifier)
		(FB_VARCHAR(32), salt)
	) data;

	Metadata()
		: param(&status, MasterInterfacePtr()), data(&status, MasterInterfacePtr())
	{ }

	Metadata(MemoryPool& p)
		: status(p), param(&status, MasterInterfacePtr()), data(&status, MasterInterfacePtr())
	{ }
};

InitInstance<Metadata> meta;

class SrpServer : public StdPlugin<IServerImpl<SrpServer, CheckStatusWrapper> >
{
public:
	explicit SrpServer(IPluginConfig* par)
		: server(NULL), data(getPool()), account(getPool()),
		  clientPubKey(getPool()), serverPubKey(getPool()),
		  verifier(getPool()), salt(getPool()), sessionKey(getPool()),
		  iParameter(par), secDbName(getPool()), cryptCallback(NULL)
	{ }

	// IServer implementation
	int authenticate(CheckStatusWrapper* status, IServerBlock* sBlock, IWriter* writerInterface);
	void setDbCryptCallback(CheckStatusWrapper* status, ICryptKeyCallback* callback);
    int release();

	~SrpServer()
	{
		delete server;
	}

private:
	RemotePassword* server;
	string data;
	string account;
	string clientPubKey, serverPubKey;
	UCharBuffer verifier;
	string salt;
	UCharBuffer sessionKey;
	RefPtr<IPluginConfig> iParameter;
	PathName secDbName;
	ICryptKeyCallback* cryptCallback;
protected:
    virtual RemotePassword* RemotePasswordFactory()=0;
};

class SecurityDatabase : public VSecDb
{
public:
	bool lookup(void* inMsg, void* outMsg)
	{
		Jrd::FbLocalStatus status;

		stmt->execute(&status, tra, meta().param.getMetadata(), inMsg,
			meta().data.getMetadata(), outMsg);
		check(&status);

		return false;	// safe default
	}

	// This 2 are needed to satisfy temporarily different calling requirements
	static int shutdown(const int, const int, void*)
	{
		return instances->shutdown();
	}
	static void cleanup()
	{
		instances->shutdown();
	}

	SecurityDatabase(const char* secDbName, ICryptKeyCallback* cryptCallback)
		: att(NULL), tra(NULL), stmt(NULL)
	{
		Jrd::FbLocalStatus status;

		DispatcherPtr p;
		if (cryptCallback)
		{
			p->setDbCryptCallback(&status, cryptCallback);
			status->init();		// ignore possible errors like missing call in provider
		}

		ClumpletWriter dpb(ClumpletReader::dpbList, MAX_DPB_SIZE);
		dpb.insertByte(isc_dpb_sec_attach, TRUE);
		dpb.insertString(isc_dpb_user_name, SYSDBA_USER_NAME, fb_strlen(SYSDBA_USER_NAME));
		dpb.insertString(isc_dpb_config, ParsedList::getNonLoopbackProviders(secDbName));
		att = p->attachDatabase(&status, secDbName, dpb.getBufferLength(), dpb.getBuffer());
		check(&status);
		HANDSHAKE_DEBUG(fprintf(stderr, "Srv SRP: attached sec db %s\n", secDbName));

		const UCHAR tpb[] =
		{
			isc_tpb_version1,
			isc_tpb_read,
			isc_tpb_read_committed,
			isc_tpb_rec_version,
			isc_tpb_wait
		};
		tra = att->startTransaction(&status, sizeof(tpb), tpb);
		check(&status);
		HANDSHAKE_DEBUG(fprintf(stderr, "Srv: SRP1: started transaction\n"));

		const char* sql =
			"SELECT PLG$VERIFIER, PLG$SALT FROM PLG$SRP WHERE PLG$USER_NAME = ? AND PLG$ACTIVE";
		stmt = att->prepare(&status, tra, 0, sql, 3, IStatement::PREPARE_PREFETCH_METADATA);
		if (status->getState() & IStatus::STATE_ERRORS)
		{
			checkStatusVectorForMissingTable(status->getErrors());
			status_exception::raise(&status);
		}
	}

private:
	IAttachment* att;
	ITransaction* tra;
	IStatement* stmt;

	~SecurityDatabase()
	{
		Jrd::FbLocalStatus status;

		stmt->free(&status);
		checkLogStatus(status);

		tra->rollback(&status);
		checkLogStatus(status);

		att->detach(&status);
		checkLogStatus(status);
	}

	void checkLogStatus(Jrd::FbLocalStatus& status)
	{
		if (!status.isSuccess())
			iscLogStatus("Srp Server", &status);
	}
};

template <class SHA> class SrpServerImpl FB_FINAL : public SrpServer  
{
public:
	explicit SrpServerImpl<SHA>(IPluginConfig* ipc)
	  : SrpServer(ipc) {}
protected:
    RemotePassword* RemotePasswordFactory()
    {
		return FB_NEW RemotePasswordImpl<SHA>;
	}
};


int SrpServer::authenticate(CheckStatusWrapper* status, IServerBlock* sb, IWriter* writerInterface)
{
	try
	{
		if (!server)
		{
			HANDSHAKE_DEBUG(fprintf(stderr, "Srv: SRP phase1\n"));

			if (!sb->getLogin())
			{
				return AUTH_CONTINUE;
			}

			account = sb->getLogin();

			unsigned int length;
			const unsigned char* val = sb->getData(&length);
			clientPubKey.assign(val, length);
			dumpBin("Srv: clientPubKey", clientPubKey);

			if (!clientPubKey.hasData())
			{
				HANDSHAKE_DEBUG(fprintf(stderr, "Srv: SRP: empty pubkey AUTH_MORE_DATA\n"));
				return AUTH_MORE_DATA;
			}

			// load verifier and salt from security database
			Metadata messages;
			messages.param->login.set(account.c_str());
			messages.param->loginNull = 0;
			messages.data.clear();

			{ // reference & mutex scope scope
				// Get database block from cache
				RefPtr<CachedSecurityDatabase> instance;
				instances->getInstance(iParameter, instance);

				try
				{
					MutexLockGuard g(instance->mutex, FB_FUNCTION);

					secDbName = instance->secureDbName;
					if (!instance->secDb)
						instance->secDb = FB_NEW SecurityDatabase(instance->secureDbName, cryptCallback);

					instance->secDb->lookup(messages.param.getData(), messages.data.getData());
				}
				catch(const Exception&)
				{
					instance->close();
					throw;
				}

				instance->close();
			}
			HANDSHAKE_DEBUG(fprintf(stderr, "Srv: SRP1: Executed statement\n"));

			verifier.assign(reinterpret_cast<const UCHAR*>(messages.data->verifier.str), messages.data->verifier.length);
			dumpIt("Srv: verifier", verifier);

			UCharBuffer s;
			s.assign(reinterpret_cast<const UCHAR*>(messages.data->salt.str), messages.data->salt.length);
			BigInteger(s).getText(salt);
			dumpIt("Srv: salt", salt);

			// create SRP-calculating server
			server = RemotePasswordFactory();
			server->genServerKey(serverPubKey, verifier);

			// Ready to prepare data for client and calculate session key
			data = "";
			fb_assert(salt.length() <= RemotePassword::SRP_SALT_SIZE * 2);
			data += char(salt.length());
			data += char(salt.length() >> 8);
			data.append(salt);
			fb_assert(serverPubKey.length() <= RemotePassword::SRP_KEY_SIZE * 2);
			data += char(serverPubKey.length());
			data += char(serverPubKey.length() >> 8);
			data.append(serverPubKey);
			dumpIt("Srv: serverPubKey", serverPubKey);
			dumpBin("Srv: data", data);
			sb->putData(status, data.length(), data.c_str());
			if (status->getState() & IStatus::STATE_ERRORS)
			{
				return AUTH_FAILED;
			}

			server->serverSessionKey(sessionKey, clientPubKey.c_str(), verifier);
			dumpIt("Srv: sessionKey", sessionKey);
			return AUTH_MORE_DATA;
		}

		unsigned int length;
		const unsigned char* val = sb->getData(&length);
		HANDSHAKE_DEBUG(fprintf(stderr, "Srv: SRP: phase2, data length is %d\n", length));
		string proof;
		proof.assign(val, length);
		BigInteger clientProof(proof.c_str());
		BigInteger serverProof = server->clientProof(account.c_str(), salt.c_str(), sessionKey);
		HANDSHAKE_DEBUG(fprintf(stderr, "Client Proof Received, Length = %d\n", clientProof.length()));
		dumpIt("Srv: Client Proof",clientProof);
		dumpIt("Srv: Server Proof",serverProof);
		if (clientProof == serverProof)
		{
			// put the record into authentication block
			writerInterface->add(status, account.c_str());
			if (status->getState() & IStatus::STATE_ERRORS)
			{
				return AUTH_FAILED;
			}
			writerInterface->setDb(status, secDbName.c_str());
			if (status->getState() & IStatus::STATE_ERRORS)
			{
				return AUTH_FAILED;
			}

			// output the key
			ICryptKey* cKey = sb->newKey(status);
			if (status->getState() & IStatus::STATE_ERRORS)
			{
				return AUTH_FAILED;
			}
			cKey->setSymmetric(status, "Symmetric", sessionKey.getCount(), sessionKey.begin());
			if (status->getState() & IStatus::STATE_ERRORS)
			{
				return AUTH_FAILED;
			}

			return AUTH_SUCCESS;
		}
	}
	catch (const Exception& ex)
	{
		status->init();
		ex.stuffException(status);
		switch(status->getErrors()[1])
		{
		case isc_stream_eof:	// User name not found in security database
			break;
		default:
			return AUTH_FAILED;
		}
	}

	status->init();
	return AUTH_CONTINUE;
}

void SrpServer::setDbCryptCallback(CheckStatusWrapper* status, ICryptKeyCallback* callback)
{
	cryptCallback = callback;
}

int SrpServer::release()
{
	if (--refCounter == 0)
	{
		delete this;
		return 0;
	}
	return 1;
}

SimpleFactory<SrpServerImpl<Sha1> > factory_sha1;
SimpleFactory<SrpServerImpl<sha224> > factory_sha224;
SimpleFactory<SrpServerImpl<sha256> > factory_sha256;
SimpleFactory<SrpServerImpl<sha384> > factory_sha384;
SimpleFactory<SrpServerImpl<sha512> > factory_sha512;

} // anonymous namespace


namespace Auth {

void registerSrpServer(IPluginManager* iPlugin)
{
	iPlugin->registerPluginFactory(IPluginManager::TYPE_AUTH_SERVER, RemotePassword::plugName, &factory_sha1);
	iPlugin->registerPluginFactory(IPluginManager::TYPE_AUTH_SERVER, RemotePassword::pluginName(224).c_str(), &factory_sha224);
	iPlugin->registerPluginFactory(IPluginManager::TYPE_AUTH_SERVER, RemotePassword::pluginName(256).c_str(), &factory_sha256);
	iPlugin->registerPluginFactory(IPluginManager::TYPE_AUTH_SERVER, RemotePassword::pluginName(384).c_str(), &factory_sha384);
	iPlugin->registerPluginFactory(IPluginManager::TYPE_AUTH_SERVER, RemotePassword::pluginName(512).c_str(), &factory_sha512);
}

} // namespace Auth
