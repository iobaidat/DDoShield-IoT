/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * tap-csma-virtual-machine.cc
 *
 * Switched + small-bus CSMA topology for DDoSim:
 *   node 0: TServer
 *   node 1: Attacker
 *   node 2: IDS
 *   nodes 3..NumNodes-1: Devs
 *
 * TServer, IDS, and the switch node (swCore) share a small CSMA bus.
 * All other nodes have their own CSMA link to swCore, which is bridged
 * with BridgeNetDevice to behave like an Ethernet switch.
 *
 * This gives:
 *   - one TAP per node,
 *   - no giant all-nodes-on-one-bus contention,
 *   - IDS on the same bus as TServer, so it sees all traffic to TServer.
 */
//
//  Topology (ns-3 side)
//
//                 Dev1          Dev2          Dev3        ...       Attacker
//                  |             |             |                        |
//                  |             |             |                        |
//                  +-------------+-------------+------------------------+
//                                |             |                        |
//                              +----------------------------------------+
//                              |                swCore                  |
//                              |          (BridgeNetDevice)            |
//                              +----------------------------------------+
//                                               |
//                                               |  (shared CSMA bus)
//                                       +-------+-------+
//                                       |               |
//                                    TServer           IDS
//
//  Notes:
//    - TServer (node 0), IDS (node 2), and swCore share a single CSMA bus.
//      * All traffic destined to TServer from Devs/Attacker passes over this bus.
//      * IDS is on this bus, so in promiscuous mode it can see all traffic to TServer.
//    - Attacker (node 1) and each Dev node (3..NumNodes-1) have their own
//      dedicated CSMA link to swCore (no shared Dev bus).
//    - swCore uses BridgeNetDevice to behave like an Ethernet switch, forwarding
//      frames between the per-node links and the TServer/IDS bus.
//    - Each node (TServer, Attacker, IDS, each Dev) has exactly one CsmaNetDevice
//      and one TAP on the host side:
//          node 0 -> 10.0.0.1  (TServer)  -> tap-<TapBaseName>1
//          node 1 -> 10.0.0.2  (Attacker) -> tap-<TapBaseName>2
//          node 2 -> 10.0.0.3  (IDS)      -> tap-<TapBaseName>3
//          node i -> 10.0.0.(i+1) (Dev_i) -> tap-<TapBaseName>(i+1) for i>=3
//

#include <iostream>
#include <sstream>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <limits>
#include <vector>
#include <time.h>
#include <sys/stat.h>

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/csma-module.h"
#include "ns3/bridge-module.h"
#include "ns3/tap-bridge-module.h"
#include "ns3/netanim-module.h"
#include "ns3/internet-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/applications-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("TapCsmaVirtualMachineExample");

// ---------------------------------------------------------------------------
//  Churn function
// ---------------------------------------------------------------------------
void
Churn (std::vector<bool>& isChurn,
       NetDeviceContainer* devs,
       int churn_lev,
       int NoneDevsNodes)
{
  double q_h, e_h, l_h, L_h;
  double phi_1 = 0.16, phi_2 = 0.08, phi_3 = 0.04;
  double churn_threshold = 0.04;
  Time dyna_churn_dur = Seconds (20);
  int NumNodes = devs->GetN ();

  for (int i = NoneDevsNodes; i < NumNodes; ++i) // no churn for TServer/Attacker/IDS
    {
      Ptr<UniformRandomVariable> x = CreateObject<UniformRandomVariable> ();

      RngSeedManager::SetSeed (time (nullptr));  // Changes seed
      RngSeedManager::SetRun (time (nullptr));   // Changes run number

      q_h = x->GetValue (0.0, 1.0);
      e_h = x->GetValue (0.0, 1.0);

      L_h = (1 - q_h) * (1 - e_h);

      if (L_h <= 0.4)
        {
          l_h = phi_1 * L_h;
        }
      else if (L_h > 0.4 && L_h <= 0.7)
        {
          l_h = phi_2 * L_h;
        }
      else
        {
          l_h = phi_3 * L_h;
        }

      double value = static_cast<int> (l_h * 100 + 0.5);
      double round_val = value / 100.0;

      NS_LOG_UNCOND ("Time:" << Simulator::Now ().ToDouble (Time::S)
                             << " Node:" << (i + 1)
                             << " q(h):" << q_h
                             << " e(h):" << e_h
                             << " L(h):" << L_h
                             << " l(h):" << l_h
                             << " p:" << round_val);

      Ptr<CsmaNetDevice> curr_csma_netdev =
        DynamicCast<CsmaNetDevice> (devs->Get (i));

      if (round_val >= churn_threshold)
        {
          isChurn[i] = true;
          curr_csma_netdev->SetAttribute ("SendEnable", BooleanValue (false));
          curr_csma_netdev->SetAttribute ("ReceiveEnable", BooleanValue (false));
        }
      else if (isChurn[i])
        {
          isChurn[i] = false;
          curr_csma_netdev->SetAttribute ("SendEnable", BooleanValue (true));
          curr_csma_netdev->SetAttribute ("ReceiveEnable", BooleanValue (true));
        }
    }

  int churn_nodes = 0;
  for (int i = NoneDevsNodes; i < NumNodes; ++i)
    {
      if (isChurn[i])
        {
          ++churn_nodes;
        }
    }
  NS_LOG_UNCOND ("churn nodes #:" << churn_nodes);

  if (churn_lev == 2)
    {
      Simulator::Schedule (dyna_churn_dur, &Churn, isChurn, devs, churn_lev, NoneDevsNodes);
    }
}

int
main (int argc, char* argv[])
{
  bool AnimationOn = false;
  int NumNodes = 10;
  int NoneDevsNodes = 3; // 0=TServer, 1=Attacker, 2=IDS
  double TotalTime = 600.0;
  int churn = 0;         // 0 => no churn, 1 => static, 2 => dynamic
  int log = 0;           // 0 => disabled, 1 => pcap, 2 => more verbose

  std::string TapBaseName = "emu";
  std::string WriteDir = "";

  LogComponentEnable ("TapCsmaVirtualMachineExample", LOG_LEVEL_ALL);

  CommandLine cmd;
  cmd.AddValue ("NumNodes", "Number of nodes", NumNodes);
  cmd.AddValue ("NoneDevsNodes", "Number of nodes other than Devs (must be 3: TServer, Attacker, IDS)", NoneDevsNodes);
  cmd.AddValue ("TotalTime", "Total simulation time", TotalTime);
  cmd.AddValue ("TapBaseName", "Base name for tap interfaces", TapBaseName);
  cmd.AddValue ("AnimationOn", "Enable animation", AnimationOn);
  cmd.AddValue ("Churn", "Churn level", churn);
  cmd.AddValue ("FileLog", "Enable log data to file", log);
  cmd.AddValue ("WriteDirectory", "Output directory for logs/pcaps", WriteDir);

  cmd.Parse (argc, argv);

  if (NoneDevsNodes != 3)
    {
      NS_FATAL_ERROR ("This topology assumes NoneDevsNodes == 3 "
                      "(0=TServer, 1=Attacker, 2=IDS).");
    }
  if (NumNodes < 4)
    {
      NS_FATAL_ERROR ("Need at least 4 nodes: TServer, Attacker, IDS, and >=1 Dev.");
    }

  // Realtime mode and checksums
  GlobalValue::Bind ("SimulatorImplementationType",
                     StringValue ("ns3::RealtimeSimulatorImpl"));
  GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));

  NS_LOG_UNCOND ("Running simulation in switched + TServer/IDS bus CSMA mode");

  // ----------------------------------------------------------------------
  //  Create ghost nodes: 0=TServer, 1=Attacker, 2=IDS, 3..=Devs
  // ----------------------------------------------------------------------
  NS_LOG_INFO ("Creating nodes");
  NodeContainer nodes;
  nodes.Create (NumNodes);

  // ----------------------------------------------------------------------
  //  Create a switch node (swCore)
  // ----------------------------------------------------------------------
  NodeContainer swCoreNode;
  swCoreNode.Create (1);
  Ptr<Node> swCore = swCoreNode.Get (0);

  CsmaHelper csma;
  // Use a very high rate so the internal simulated links are not the bottleneck.
  csma.SetChannelAttribute ("DataRate", StringValue ("100Gbps"));
  csma.SetChannelAttribute ("Delay", TimeValue (NanoSeconds (6560)));

  // For each node i, nodeDevs[i] will be its single CsmaNetDevice
  std::vector<Ptr<NetDevice>> nodeDevs (NumNodes);
  NetDeviceContainer swCorePorts;

  // ---- Small bus: TServer (0), IDS (2), and swCore share one CSMA channel ----
  NodeContainer busNodes;
  busNodes.Add (nodes.Get (0)); // TServer
  busNodes.Add (nodes.Get (2)); // IDS
  busNodes.Add (swCore);
  NetDeviceContainer busDevs = csma.Install (busNodes);
  // Order: 0->TServer, 1->IDS, 2->swCore
  nodeDevs[0] = busDevs.Get (0);
  nodeDevs[2] = busDevs.Get (1);
  swCorePorts.Add (busDevs.Get (2)); // swCore port on the bus

  // ---- Attacker (1) gets its own link to swCore ----
  {
    NetDeviceContainer link = csma.Install (NodeContainer (nodes.Get (1), swCore));
    nodeDevs[1] = link.Get (0);      // Attacker NIC
    swCorePorts.Add (link.Get (1));  // swCore port
  }

  // ---- Devs [3..NumNodes-1] each get their own link to swCore ----
  for (int i = 3; i < NumNodes; ++i)
    {
      NetDeviceContainer link = csma.Install (NodeContainer (nodes.Get (i), swCore));
      nodeDevs[i] = link.Get (0);      // Dev NIC
      swCorePorts.Add (link.Get (1));  // swCore port
    }

  // ---- swCore behaves like a switch, bridging all ports ----
  BridgeHelper bridge;
  bridge.Install (swCore, swCorePorts);

  // Build a NetDeviceContainer in node index order for IP, churn, TAP
  NetDeviceContainer devices;
  for (int i = 0; i < NumNodes; ++i)
    {
      devices.Add (nodeDevs[i]);
    }

  // ----------------------------------------------------------------------
  //  Internet stack & IP addressing
  // ----------------------------------------------------------------------
  InternetStackHelper internetRight;
  internetRight.Install (nodes);

  Ipv4AddressHelper ipv4Right;
  //   node 0 -> 10.0.0.1 (TServer)
  //   node 1 -> 10.0.0.2 (Attacker)
  //   node 2 -> 10.0.0.3 (IDS)
  //   node i -> 10.0.0.(i+1) for i >= 3 (Devs)
  ipv4Right.SetBase ("10.0.0.0", "255.0.0.0");
  Ipv4InterfaceContainer interfacesRight = ipv4Right.Assign (devices);
  (void) interfacesRight; // silence unused warning if not used further

  // ----------------------------------------------------------------------
  //  TAP bridges: one TAP per node, matching node index + 1
  // ----------------------------------------------------------------------
  NS_LOG_INFO ("Creating tap bridges");
  TapBridgeHelper tapBridge;
  tapBridge.SetAttribute ("Mode", StringValue ("UseBridge"));

  for (int i = 0; i < NumNodes; ++i)
    {
      std::stringstream tapName;
      tapName << "tap-" << TapBaseName << (i + 1);
      NS_LOG_INFO ("Tap bridge = " << tapName.str ());

      tapBridge.SetAttribute ("DeviceName", StringValue (tapName.str ()));
      tapBridge.Install (nodes.Get (i), devices.Get (i));
    }

  // ----------------------------------------------------------------------
  //  Churn (only Devs: i >= NoneDevsNodes == 3)
  // ----------------------------------------------------------------------
  if (churn != 0)
    {
      std::vector<bool> isChurn (NumNodes + 1, false);
      Churn (isChurn, &devices, churn, NoneDevsNodes);
    }

  // ----------------------------------------------------------------------
  //  Print TServer NIC info for debugging
  // ----------------------------------------------------------------------
  Ptr<NetDevice> PtrNetDevice;
  {
    Ptr<Node> PtrNode = nodes.Get (0);
    PtrNetDevice = PtrNode->GetDevice (0);
    Ptr<Ipv4> ipv4 = PtrNode->GetObject<Ipv4> ();
    Ipv4InterfaceAddress iaddr = ipv4->GetAddress (1, 0);
    Ipv4Address ipAddr = iaddr.GetLocal ();

    std::cout << "\n****************************************"
              << "\nTarget Server IPv4: " << ipAddr
              << "\nTarget Server MAC: " << PtrNetDevice->GetAddress ()
              << "\n****************************************\n\n";
  }

  // ----------------------------------------------------------------------
  //  NetAnim (optional)
  // ----------------------------------------------------------------------
  if (AnimationOn)
    {
      NS_LOG_UNCOND ("Activating Animation");
      AnimationInterface anim ("animation.xml");
      for (uint32_t i = 0; i < nodes.GetN (); ++i)
        {
          std::stringstream ssi;
          ssi << i;
          anim.UpdateNodeDescription (nodes.Get (i), "Node" + ssi.str ());
          anim.UpdateNodeColor (nodes.Get (i), 255, 0, 0);
        }

      anim.EnablePacketMetadata ();
      anim.EnableWifiMacCounters (Seconds (0), Seconds (TotalTime));
      anim.EnableWifiPhyCounters (Seconds (0), Seconds (TotalTime));
    }

  // ----------------------------------------------------------------------
  //  Routing & pcap
  // ----------------------------------------------------------------------
  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

  if (log)
    {
      // Check output directory exists
      struct stat buffer;
      if (stat (WriteDir.c_str (), &buffer) != 0)
        {
          NS_FATAL_ERROR ("\"" << WriteDir << "\" folder does not exist");
        }

      std::string outputf =
        WriteDir + "/captured_packets_csma_" + std::to_string (NumNodes - NoneDevsNodes);
      csma.EnablePcap (outputf, PtrNetDevice, true);
    }

  // ----------------------------------------------------------------------
  //  Run
  // ----------------------------------------------------------------------
  Simulator::Stop (Seconds (TotalTime));
  Simulator::Run ();
  Simulator::Destroy ();

  return 0;
}