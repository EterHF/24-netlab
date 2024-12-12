#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/traffic-control-module.h"

#include <fstream>
#include <iostream>
#include <string>
#include <sys/stat.h>

using namespace ns3;

// - Network topology
//   - The dumbbell topology consists of 
//     - 4 servers (S0, S1, R0, R1)
//     - 2 routers (T0, T1) 
//   - The topology is as follows:
//
//                    S0                         R0
//     10 Mbps, 1 ms   |      1 Mbps, 10 ms       |   10 Mbps, 1 ms
//                    T0 ----------------------- T1
//     10 Mbps, 1 ms   |                          |   10 Mbps, 1 ms
//                    S1                         R1
//
// - Two TCP flows:
//   - TCP flow 0 from S0 to R0 using BulkSendApplication.
//   - TCP flow 1 from S1 to R1 using BulkSendApplication.

const uint32_t N1 = 2;    // Number of nodes in left side
const uint32_t N2 = 2;    // Number of nodes in right side
uint32_t segmentSize = 1448;    // Segment size
Time startTime = Seconds(10.0);    // Start time for the simulation
Time stopTime = Seconds(60.0);    // Stop time for the simulation

uint32_t flow_size_0 = 0, flow_size_1 = 0;
uint32_t max_seq_num_0 = 0, max_seq_num_1 = 0;
int64_t start_0, start_1, end_0 = 0, end_1 = 0;
bool ended_0 = false, ended_1 = false, ended_all = false;
std::vector<uint32_t> flow_sizes;
std::string pcap_dir = "lv1-results/pcap/";
std::string cwnd_dir = "lv1-results/cwnd/";
std::string fct_dir = "lv1-results/fct/";

// parse flow size
void argparser(int argc, char* argv[]){
    CommandLine cmd;
    cmd.AddValue("flowSize0", "Flow size 0", flow_size_0);
    cmd.AddValue("flowSize1", "Flow size 1", flow_size_1);
    cmd.Parse(argc, argv); // !!!!!先Parse再push_back
    flow_sizes.push_back(flow_size_0);
    flow_sizes.push_back(flow_size_1);
}

// callback func of cwnd change
static void CwndChange(uint32_t nodeId, uint32_t oldCwnd, uint32_t newCwnd){
    std::string filename = cwnd_dir + "n" + std::to_string(nodeId) + ".dat";
    std::ofstream outFile(filename, std::ios::out | std::ios::app);
    
    if (outFile.is_open()){
        outFile << Simulator::Now().GetMicroSeconds() << " "
                << oldCwnd / segmentSize << " "
                << newCwnd / segmentSize << std::endl;
        outFile.close();
    }
    else{
        std::cerr << "Error opening file: " << filename << std::endl;
    }
}

// Trace cwnd
void TraceCwnd(uint32_t nodeId, uint32_t socketId){
    std::string tracePath = "/NodeList/" + std::to_string(nodeId) +
                            "/$ns3::TcpL4Protocol/SocketList/" +
                            std::to_string(socketId) + "/CongestionWindow";
    Config::ConnectWithoutContext(tracePath, MakeBoundCallback(&CwndChange, nodeId));
}

// callback func of tracing fct
void TxChange(int flowId, Ptr<const Packet> packet, const TcpHeader& header, Ptr<const TcpSocketBase> socket){
    uint32_t extraFlagBytes = 0;
    if (header.GetFlags() & TcpHeader::SYN) {
        extraFlagBytes += 1;
    }
    if (header.GetFlags() & TcpHeader::FIN) {
        extraFlagBytes += 1;
    }

    if(flowId == 0) max_seq_num_0 = std::max(max_seq_num_0, header.GetSequenceNumber().GetValue() + packet->GetSize() + extraFlagBytes - 1);
    else max_seq_num_1 = std::max(max_seq_num_1, header.GetSequenceNumber().GetValue() + packet->GetSize() + extraFlagBytes - 1);
}

void RxChange(int flowId, Ptr<const Packet> packet, const TcpHeader& header, Ptr<const TcpSocketBase> socket){
    if(header.GetFlags() == (TcpHeader::FIN | TcpHeader::ACK)){
        // if(flowId == 0) std::cout<<Simulator::Now().GetMicroSeconds() - start_0<<std::endl;
        // else std::cout<<Simulator::Now().GetMicroSeconds() - start_1<<std::endl;
        // std::cout<<1<<std::endl;
        if(flowId == 0){ // 取最后一次的 FIN | ACK
            end_0 = Simulator::Now().GetMicroSeconds();
            ended_0 = true;
        }
        else if(flowId == 1){
            end_1 = Simulator::Now().GetMicroSeconds();
            ended_1 = true;
        }
    }
    if(ended_0 && ended_1 && !ended_all){
        std::ofstream outFile(fct_dir + "fct.dat", std::ios::out);
        if(outFile.is_open()){
            outFile << end_0 - start_0 << std::endl
                    << end_1 - start_1 << std::endl;
            outFile.close();
            ended_all = true;
        }
        else{
            std::cerr << "Error opening file: " << fct_dir + "fct.dat" << std::endl;
        }
    }
}

// state change
void StateChange(int flowId, TcpSocket::TcpStates_t old_state, TcpSocket::TcpStates_t new_state){
    if(new_state == TcpSocket::TIME_WAIT){
        if(flowId == 0){
            end_0 = Simulator::Now().GetMicroSeconds();
            ended_0 = true;
        }
        else if(flowId == 1){
            end_1 = Simulator::Now().GetMicroSeconds();
            ended_1 = true;
        }
    }
    if(ended_0 && ended_1 && !ended_all){
        std::ofstream outFile(fct_dir + "fct.dat", std::ios::out);
        if(outFile.is_open()){
            outFile << end_0 - start_0 << std::endl
                    << end_1 - start_1 << std::endl;
            outFile.close();
            ended_all = true;
        }
        else{
            std::cerr << "Error opening file: " << fct_dir + "fct.dat" << std::endl;
        }
    }
}

// Trace fct
void TraceFCT(ApplicationContainer sourceApps, int flowId){
    Ptr<BulkSendApplication> bulk_app = sourceApps.Get(0)->GetObject<BulkSendApplication>();
    Ptr<ns3::Socket> socket = bulk_app->GetSocket();
    // ocket->TraceConnectWithoutContext("Tx", MakeBoundCallback(&TxChange, flowId));
    socket->TraceConnectWithoutContext("Rx", MakeBoundCallback(&RxChange, flowId));
    // socket->TraceConnectWithoutContext("State", MakeBoundCallback(&StateChange, flowId));
}

// Function to install BulkSend application
void
InstallBulkSend(Ptr<Node> node,
                Ipv4Address address,
                uint16_t port,
                std::string socketFactory,
                int flowId,
                uint32_t flowSize)
{
    BulkSendHelper source(socketFactory, InetSocketAddress(address, port));
    // std::cout<<"Target address: "<<address<<std::endl;
    source.SetAttribute("MaxBytes", UintegerValue(flowSize));    // "0" means there is no limit. This line should be changed in Exercise 1.2
    ApplicationContainer sourceApps = source.Install(node);

    sourceApps.Start(startTime);
    if(flowId == 0) start_0 = startTime.GetMicroSeconds();
    else start_1 = startTime.GetMicroSeconds();
    Simulator::Schedule(startTime + TimeStep(1), &TraceCwnd, node->GetId(), 0);
    Simulator::Schedule(startTime + TimeStep(2), &TraceFCT, sourceApps, flowId);
    sourceApps.Stop(stopTime);
}

// Function to install sink application
void
InstallPacketSink(Ptr<Node> node, uint16_t port, std::string socketFactory)
{
    PacketSinkHelper sink(socketFactory, InetSocketAddress(Ipv4Address::GetAny(), port));
    ApplicationContainer sinkApps = sink.Install(node);
    sinkApps.Start(startTime);
    sinkApps.Stop(stopTime);
}

int
main(int argc, char* argv[])
{
    argparser(argc, argv);
    std::string socketFactory = "ns3::TcpSocketFactory";    // Socket factory to use
    std::string tcpTypeId = "ns3::TcpLinuxReno";    // TCP variant to use
    std::string qdiscTypeId = "ns3::FifoQueueDisc";    // Queue disc for gateway
    bool isSack = true;    // Flag to enable/disable sack in TCP
    uint32_t delAckCount = 1;    // Delayed ack count
    std::string recovery = "ns3::TcpClassicRecovery";    // Recovery algorithm type to use

    // Check if the qdiscTypeId and tcpTypeId are valid
    TypeId qdTid;
    NS_ABORT_MSG_UNLESS(TypeId::LookupByNameFailSafe(qdiscTypeId, &qdTid),
                        "TypeId " << qdiscTypeId << " not found");
    TypeId tcpTid;
    NS_ABORT_MSG_UNLESS(TypeId::LookupByNameFailSafe(tcpTypeId, &tcpTid),
                        "TypeId " << tcpTypeId << " not found");

    // Set recovery algorithm and TCP variant
    Config::SetDefault("ns3::TcpL4Protocol::RecoveryType",
                       TypeIdValue(TypeId::LookupByName(recovery)));
    Config::SetDefault("ns3::TcpL4Protocol::SocketType",
                       TypeIdValue(TypeId::LookupByName(tcpTypeId)));

    // Create nodes
    NodeContainer leftNodes;
    NodeContainer rightNodes;
    NodeContainer routers;
    routers.Create(2);
    leftNodes.Create(N1);
    rightNodes.Create(N2);

    // Create the point-to-point link helpers and connect two router nodes
    PointToPointHelper pointToPointRouter;
    pointToPointRouter.SetDeviceAttribute("DataRate", StringValue("1Mbps"));
    pointToPointRouter.SetChannelAttribute("Delay", StringValue("10ms"));

    NetDeviceContainer routerToRouter = pointToPointRouter.Install(routers.Get(0), routers.Get(1));

    // Create the point-to-point link helpers and connect leaf nodes to router
    PointToPointHelper pointToPointLeaf;
    pointToPointLeaf.SetDeviceAttribute("DataRate", StringValue("10Mbps"));
    pointToPointLeaf.SetChannelAttribute("Delay", StringValue("1ms"));

    std::vector<NetDeviceContainer> leftToRouter;
    std::vector<NetDeviceContainer> routerToRight;
    for (uint32_t i = 0; i < N1; i++)
    {
        leftToRouter.push_back(pointToPointLeaf.Install(leftNodes.Get(i), routers.Get(0)));
    }
    for (uint32_t i = 0; i < N2; i++)
    {
        routerToRight.push_back(pointToPointLeaf.Install(routers.Get(1), rightNodes.Get(i)));
    }

    // Install internet stack on all the nodes
    InternetStackHelper internetStack;

    internetStack.Install(leftNodes);
    internetStack.Install(rightNodes);
    internetStack.Install(routers);

    // Assign IP addresses to all the network devices
    Ipv4AddressHelper ipAddresses("10.0.0.0", "255.255.255.0");

    Ipv4InterfaceContainer routersIpAddress = ipAddresses.Assign(routerToRouter);
    ipAddresses.NewNetwork();

    std::vector<Ipv4InterfaceContainer> leftToRouterIPAddress;
    for (uint32_t i = 0; i < N1; i++)
    {
        leftToRouterIPAddress.push_back(ipAddresses.Assign(leftToRouter[i]));
        ipAddresses.NewNetwork();
    }

    std::vector<Ipv4InterfaceContainer> routerToRightIPAddress;
    for (uint32_t i = 0; i < N2; i++)
    {
        routerToRightIPAddress.push_back(ipAddresses.Assign(routerToRight[i]));
        ipAddresses.NewNetwork();
    }

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // Set default sender and receiver buffer size as 1MB
    Config::SetDefault("ns3::TcpSocket::SndBufSize", UintegerValue(1 << 20));
    Config::SetDefault("ns3::TcpSocket::RcvBufSize", UintegerValue(1 << 20));

    // Set default initial congestion window as 10 segments
    Config::SetDefault("ns3::TcpSocket::InitialCwnd", UintegerValue(10));

    // Set default delayed ack count to a specified value
    Config::SetDefault("ns3::TcpSocket::DelAckCount", UintegerValue(delAckCount));

    // Set default segment size of TCP packet to a specified value
    Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(segmentSize));

    // Enable/Disable SACK in TCP
    Config::SetDefault("ns3::TcpSocketBase::Sack", BooleanValue(isSack));

    // Set default parameters for queue discipline
    Config::SetDefault(qdiscTypeId + "::MaxSize", QueueSizeValue(QueueSize("100p")));

    // Install queue discipline on router
    TrafficControlHelper tch;
    tch.SetRootQueueDisc(qdiscTypeId);
    QueueDiscContainer qd;
    tch.Uninstall(routers.Get(0)->GetDevice(0));
    qd.Add(tch.Install(routers.Get(0)->GetDevice(0)).Get(0));

    // Enable BQL
    tch.SetQueueLimits("ns3::DynamicQueueLimits");

    // Install packet sink at receiver side
    for (uint32_t i = 0; i < N2; i++)
    {
        uint16_t port = 50000 + i;
        InstallPacketSink(rightNodes.Get(i), port, "ns3::TcpSocketFactory");
    }

    for (uint32_t i = 0; i < N1; i++)
    {
        uint16_t port = 50000 + i;
        InstallBulkSend(leftNodes.Get(i),
                        routerToRightIPAddress[i].GetAddress(1),
                        port,
                        socketFactory,
                        i,
                        flow_sizes[i]);
    }

    // PCAP
    int ret = system(("rm -r " + pcap_dir).c_str());
    ret = system(("mkdir -p " + pcap_dir).c_str());
    NS_ASSERT_MSG(ret == 0, "Error in return value");
    pointToPointRouter.EnablePcap(pcap_dir + "lv1", routerToRouter.Get(0), true);
    pointToPointLeaf.EnablePcap(pcap_dir + "lv1", leftToRouter[0].Get(1), true);
    pointToPointLeaf.EnablePcap(pcap_dir + "lv1", leftToRouter[1].Get(1), true);

    // cwnd
    ret = system(("rm -r " + cwnd_dir).c_str());
    ret = system(("mkdir -p " + cwnd_dir).c_str());
    NS_ASSERT_MSG(ret == 0, "Error in return value");

    // fct
    ret = system(("rm -r " + fct_dir).c_str());
    ret = system(("mkdir -p " + fct_dir).c_str());
    NS_ASSERT_MSG(ret == 0, "Error in return value");

    // Set the stop time of the simulation
    Simulator::Stop(stopTime);

    // Start the simulation
    Simulator::Run();

    // Cleanup and close the simulation
    Simulator::Destroy();

    return 0;
}
