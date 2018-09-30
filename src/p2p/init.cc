
#include <netbase.h>
#include <netaddress.h>
#include <scheduler.h>
#include <net_processing.h>
#include <chainparams.h>
#include <init.h>
#include <shutdown.h>
#include <logging.h>
#include <rpc/rpc_server.h>

#define PACKAGE_NAME "P2P"
#ifndef WIN32
#include <signal.h>
#endif

CCriticalSection cs_vNodes;
std::unique_ptr<CConnman> g_connman;
PeerLogicValidation *peerLogic;   //TODO: protoype  std::unique_ptr<PeerLogicValidation>
static CScheduler scheduler;
extern std::unique_ptr<ambr::rpc::RpcServer> p_rpc;

static const bool DEFAULT_PROXYRANDOMIZE = true;
ServiceFlags nLocalServices = ServiceFlags(NODE_NETWORK | NODE_NETWORK_LIMITED);

int nMaxConnections = 12;

#ifndef WIN32
static void registerSignalHandler(int signal, void(*handler)(int))
{
    struct sigaction sa;
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(signal, &sa, nullptr);
}

static void HandleSIGTERM(int)
{
    std::cout << "Start Shutdown...." << std::endl;
    StartShutdown();
}
#endif

void ambr::p2p::SendMessage(CNode* p_node, CSerializedNetMsg&& msg){
     assert(g_connman);
     g_connman->PushMessage(p_node, std::forward<CSerializedNetMsg>(msg));
}

void ambr::p2p::BoardcastMessage(CSerializedNetMsg&& msg){
    assert(g_connman);
    LOCK(cs_vNodes);
    for (CNode* pnode : g_connman->GetNodes()) {
        SendMessage(pnode, std::forward<CSerializedNetMsg>(msg));
    }

}

void ambr::p2p::RemoveNode(CNode* pNode){
    pNode->fDisconnect = true;
}


void ambr::p2p::Interrupt(){
  if (g_connman)
    g_connman->Interrupt();
}

void ambr::p2p::WaitForShutdown(){
  while (!ShutdownRequested()){
    MilliSleep(200);
  }

  Interrupt();
}

void ambr::p2p::Shutdown(){
  LogPrintf("%s: In progress...\n", __func__);
  static CCriticalSection cs_Shutdown;

  TRY_LOCK(cs_Shutdown, lockShutdown);

   // StopRPC();
   // StopHTTPServer();


    // Because these depend on each-other, we make sure that neither can be
    // using the other before destroying them.
  if (g_connman) g_connman->Stop();
    //peerLogic.reset();
  g_connman.reset();

  if(p_rpc){
     LogPrintf("Stop RPC Server ...\n");
     p_rpc->StopRpcServer();
  }
  p_rpc.reset();

  /*
  if(p_store_manager){
     LogPrintf("Close Database ...\n");
     //TODO: Call Close DB function
  }
   p_store_manager.reset();
    */
}

void InitLogging()
{
    g_logger->m_print_to_file = true;
    g_logger->m_file_path = AbsPathForConfigVal(gArgs.GetArg("-debuglogfile", DEFAULT_DEBUGLOGFILE));

    // Add newlines to the logfile to distinguish this execution from the last
    // one; called before console logging is set up, so this is only sent to
    // debug.log.
    LogPrintf("\n\n\n\n\n");

    g_logger->m_print_to_console = gArgs.GetBoolArg("-printtoconsole", !gArgs.GetBoolArg("-daemon", false));
    g_logger->m_log_timestamps = gArgs.GetBoolArg("-logtimestamps", DEFAULT_LOGTIMESTAMPS);
    g_logger->m_log_time_micros = gArgs.GetBoolArg("-logtimemicros", DEFAULT_LOGTIMEMICROS);

    fLogIPs = gArgs.GetBoolArg("-logips", DEFAULT_LOGIPS);

    std::string version_string = std::to_string(P2P_VERSION);
#ifdef DEBUG
    version_string += " (debug build)";
#else
    version_string += " (release build)";
#endif
    LogPrintf(PACKAGE_NAME " version %s\n", version_string);
}

bool ambr::p2p::init(CConnman::Options&& connOptions){
    /*TODO import config from some class or files
    options:
        onlynet
        dns
        proxyrandomize
        proxy
        upnp
        addnode
        bind   --bind address
        whitebind
        whitelist
        seednode
        connect

    */

    if (gArgs.IsArgSet("-onlynet")) {
        std::set<enum Network> nets;
        for (const std::string& snet : gArgs.GetArgs("-onlynet")) {
            enum Network net = ParseNetwork(snet);
            if (net == NET_UNROUTABLE){
                strprintf(_("Unknown network specified in -onlynet: '%s'"), snet);
                std::cerr << snet << std::endl;
                return false;
            }

            nets.insert(net);
        }
        for (int n = 0; n < NET_MAX; n++) {
            enum Network net = (enum Network)n;
            if (!nets.count(net))
                SetLimited(net);
        }
    }

   // Check for -testnet or -regtest parameter (Params() calls are only valid after this clause)
    try {
        SelectParams(gArgs.GetChainName(), connOptions.nListenPort);
    } catch (const std::exception& e) {
        fprintf(stderr, "Error: %s\n", e.what());
        return false;
    }
    // Check for host lookup allowed before parsing any network related parameters
    InitLogging();
    fNameLookup = gArgs.GetBoolArg("-dns", DEFAULT_NAME_LOOKUP);

    bool proxyRandomize = gArgs.GetBoolArg("-proxyrandomize", DEFAULT_PROXYRANDOMIZE);
    // -proxy sets a proxy for all outgoing network traffic
    // -noproxy (or -proxy=0) as well as the empty string can be used to not set a proxy, this is the default
    std::string proxyArg = gArgs.GetArg("-proxy", "");
    SetLimited(NET_ONION);
    if (proxyArg != "" && proxyArg != "0") {
        CService proxyAddr;
        if (!Lookup(proxyArg.c_str(), proxyAddr, 9050, fNameLookup)) {
         std::cerr <<"Invalid -proxy address or hostname:" << proxyArg << std::endl;
         return false;
     }

     proxyType addrProxy = proxyType(proxyAddr, proxyRandomize);
     if (!addrProxy.IsValid()){
         std::cerr << "Invalid -proxy address or hostname:" << proxyArg << std::endl;
         return false;
     }

     SetProxy(NET_IPV4, addrProxy);
     SetProxy(NET_IPV6, addrProxy);
     SetProxy(NET_ONION, addrProxy);
     SetNameProxy(addrProxy);
     SetLimited(NET_ONION, false); // by default, -proxy sets onion as reachable, unless -noonion later
    }
    Discover();

    // Map ports with UPnP
#ifdef USE_UPNP
    StartMapPort();
    std::this_thread::sleep_for(std::chrono::milliseconds(3000));
#endif

    //assert(!g_connman);
    if(g_connman){
        g_connman.reset();
    }
    g_connman = std::unique_ptr<CConnman>(new CConnman(ambr::p2p::GetRand(std::numeric_limits<uint64_t>::max()), ambr::p2p::GetRand(std::numeric_limits<uint64_t>::max())));
    CConnman& connman = *g_connman;
    peerLogic = (new PeerLogicValidation(&connman, scheduler, false));
   // RegisterValidationInterface(peerLogic.get());

    connOptions.nLocalServices = nLocalServices;
    connOptions.nMaxConnections = nMaxConnections;
    connOptions.nMaxOutbound = std::min(MAX_OUTBOUND_CONNECTIONS, connOptions.nMaxConnections);
    connOptions.nMaxAddnode = MAX_ADDNODE_CONNECTIONS;

    connOptions.m_msgproc = peerLogic;

    connOptions.m_added_nodes = gArgs.GetArgs("-addnode");


/*
    for (const std::string& strBind : connOptions.vBindAddress) {
        CService addrBind;
        if (!Lookup(strBind.c_str(), addrBind, GetListenPort(), false)) {
            std::cerr <<"Invalid -bind address or hostname: " << strBind << std::endl;
            return false;
        }
        connOptions.vBinds.push_back(addrBind);
    }
*/
    for (const std::string& strBind : gArgs.GetArgs("-whitebind")) {
        CService addrBind;
        if (!Lookup(strBind.c_str(), addrBind, 0, false)) {
         std::cerr <<"Invalid -whitebind address or hostname: " << strBind << std::endl;
         return false;
     }
     if (addrBind.GetPort() == 0) {
         std::cerr <<"Invalid -whitebind address or hostname: "  << std::endl;
         return false;
     }
     connOptions.vWhiteBinds.push_back(addrBind);
 }

    for (const auto& net : gArgs.GetArgs("-whitelist")) {
       CSubNet subnet;
       LookupSubNet(net.c_str(), subnet);
       if (!subnet.IsValid()){
        std::cerr <<"Invalid netmask specified in -whitelist: "  << net << std::endl;
        return false;
    }

    connOptions.vWhitelistedRange.push_back(subnet);
   }

   connOptions.vSeedNodes = gArgs.GetArgs("-seednode");

       // Initiate outbound connections unless connect=0

   connOptions.m_use_addrman_outgoing = !gArgs.IsArgSet("-connect");
   if (!connOptions.m_use_addrman_outgoing) {
       const auto connect = gArgs.GetArgs("-connect");
       if (connect.size() != 1 || connect[0] != "0") {
           connOptions.m_specified_outgoing = connect;
       }
   }

       // Clean shutdown on SIGTERM
   #ifndef WIN32
   registerSignalHandler(SIGTERM, HandleSIGTERM);
   registerSignalHandler(SIGINT, HandleSIGTERM);
   #endif

   bool ret = g_connman->Start(scheduler, connOptions);

    if(ret){
      WaitForShutdown();
    }
    else{
      Interrupt();
    }
    Shutdown();

    return ret;
}

