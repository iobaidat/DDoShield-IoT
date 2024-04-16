/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


// Large Scale Simulations with ns3 using linux namespace
// PROBLEMS :(
// https://groups.google.com/forum/#!topic/ns-3-users/zy2VIrgh-Qo


// Running NS3 optimized
// ./waf distclean
// ./waf -d optimized configure --disable-examples --disable-tests --no-task-lines
// ./waf

// Running NS3 with MPI
// https://www.nsnam.org/docs/models/html/distributed.html#current-implementation-details
// it seems not feasible due to AWS restrictions, MAYBE it works in a dedicated server


//
// This is an illustration of how one could use virtualization techniques to
// allow running applications on virtual machines talking over simulated
// networks.
//
// The actual steps required to configure the virtual machines can be rather
// involved, so we don't go into that here.  Please have a look at one of
// our HOWTOs on the nsnam wiki for more details about how to get the
// system confgured.  For an example, have a look at "HOWTO Use Linux
// Containers to set up virtual networks" which uses this code as an
// example.
//
// The configuration you are after is explained in great detail in the
// HOWTO, but looks like the following:
//
//  +----------+                           +----------+
//  | virtual  |                           | virtual  |
//  |  Linux   |                           |  Linux   |
//  |   Host   |                           |   Host   |
//  |          |                           |          |
//  |   eth0   |                           |   eth0   |
//  +----------+                           +----------+
//       |                                      |
//  +----------+                           +----------+
//  |  Linux   |                           |  Linux   |
//  |  Bridge  |                           |  Bridge  |
//  +----------+                           +----------+
//       |                                      |
//  +------------+                       +-------------+
//  | "tap-left" |                       | "tap-right" |
//  +------------+                       +-------------+
//       |           n0            n*           |
//       |       +--------+    +--------+       |
//       +-------|  tap   |    |  tap   |-------+
//               | bridge |    | bridge |
//               +--------+    +--------+
//               |  wifi  |    |  wifi  |
//               +--------+    +--------+
//                   |             |
//                 ((*))         ((*))
//
//                       Wifi LAN
//
//                        ((*))
//                          |
//                     +--------+
//                     |  wifi  |
//                     +--------+
//                     | access |
//                     |  point |
//                     +--------+
//

#include <iostream>
#include <sstream>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <limits>
#include <time.h>
#include <sys/stat.h>

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/tap-bridge-module.h"
//#include "ns3/mpi-interface.h"

#include "ns3/netanim-module.h"

#include "ns3/internet-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/applications-module.h"

#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/tap-bridge-module.h"


using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("TapWifiVirtualMachineExample");


void
Churn(bool isChurn[], NetDeviceContainer *devs, int churn_lev, int NoneDevsNodes)
{
  double q_h, e_h, l_h,L_h;
  double phi_1 = 0.16, phi_2 = 0.08, phi_3 = 0.04;
  double churn_threshold = 0.04;
  Time dyna_churn_dur = Seconds(20); 
  int NumNodes = (*devs).GetN();

  for (int i = NoneDevsNodes; i < NumNodes; i++) // no churn for TServer, Attacker, and IDS
  {
    Ptr<UniformRandomVariable> x = CreateObject<UniformRandomVariable>();

    RngSeedManager::SetSeed(time(NULL));  // Changes seed
    RngSeedManager::SetRun(time(NULL));   // Changes run number

    q_h = x->GetValue(0, 1);
    e_h = x->GetValue(0, 1);

    L_h = (1 - q_h) * (1 - e_h);

    if (L_h <= 0.4)
      l_h = phi_1 * L_h;
    else if (L_h > 0.4 && L_h <= 0.7)
      l_h = phi_2 * L_h;
    else
      l_h = phi_3 * L_h;

    double value = (int)(l_h * 100 + .5);
    double round_val =  (double)value / 100;

    NS_LOG_UNCOND("Time:"<< Simulator::Now().ToDouble(ns3::Time::S)
      <<" Node:"<<(i+1)<<" q(h):" << (q_h)<<" e(h):" << (e_h)
      <<" L(h):" << (L_h)<<" l(h):" << (l_h)<<" p:"<<round_val<<"\n");

    Ptr<WifiNetDevice> curr_wifi_net = DynamicCast<WifiNetDevice>((*devs).Get(i));
    Ptr<WifiPhy> curr_wifi_py = DynamicCast<WifiPhy>(curr_wifi_net->GetPhy());
    Ptr<WifiPhyStateHelper> state_phy = curr_wifi_py->GetState();

    if (round_val >= churn_threshold)
    {
      isChurn[i] = true;
      NS_LOG_UNCOND("\nNode = "<<(i+1)<<" churn off before: "<<!(state_phy->IsStateOff()));
      if (!(state_phy->IsStateOff()))
      {
        state_phy->SwitchToOff();
      }
      NS_LOG_UNCOND("Node = "<<(i+1)<<" churn off after: "<<!(state_phy->IsStateOff()));
    }
    else if (isChurn[i])
    {
      isChurn[i] = false;
      NS_LOG_UNCOND("\nNode = "<<(i+1)<<" churn on before: "<<!(state_phy->IsStateOff()));
      if (state_phy->IsStateOff())
      {
        state_phy->SwitchFromOff();
      }
      NS_LOG_UNCOND("Node = "<<(i+1)<<" churn on after: "<<!(state_phy->IsStateOff()));
    }
  }

  int churn_nodes = 0;
  for(int i = 3; i < NumNodes; i++)
  {
      if (isChurn[i])
      {
        churn_nodes++;
      }
  }
  NS_LOG_INFO("churn nodes #:"<<churn_nodes<<"\n");

  if (churn_lev == 2)
    Simulator::Schedule (dyna_churn_dur, &Churn, isChurn, devs, churn_lev, NoneDevsNodes);
}


int
main (int argc, char *argv[])
{
  bool AnimationOn = false;
  int NumNodes = 10;
  double TotalTime = 600.0;
  int NoneDevsNodes = 1;
  double distance = 5;  // m

  int churn = 0; // 0 => no churn, 1 => static, 2 => dynamic
  int log = 0;   // 0 => disabled, 1 => log stats, 2 => log all

  std::string TapBaseName = "emu";
  std::string mode = "UseLocal";

  std::string WriteDir = "";

  LogComponentEnable ("TapWifiVirtualMachineExample", LOG_LEVEL_ALL); //LOG_LEVEL_DEBUG //LOG_LEVEL_INFO

  CommandLine cmd;
  cmd.AddValue ("NumNodes", "Number of nodes", NumNodes);
  cmd.AddValue ("NoneDevsNodes", "Number of nodes other than Devs", NoneDevsNodes);
  cmd.AddValue ("TotalTime", "Total simulation time", TotalTime);
  cmd.AddValue ("TapBaseName", "Base name for tap interfaces", TapBaseName);
  cmd.AddValue ("DiskDistance", "Disk distance", distance);
  cmd.AddValue ("AnimationOn", "Enable animation", AnimationOn);
  cmd.AddValue ("Churn", "Churn level", churn);
  cmd.AddValue ("FileLog", "Enable log data to file", log);
  cmd.AddValue ("WriteDirectory", "Enable log data to file", WriteDir);

  cmd.Parse (argc,argv);

  //
  // We are interacting with the outside, real, world.  This means we have to
  // interact in real-time and therefore means we have to use the real-time
  // simulator and take the time to calculate checksums.
  //
  GlobalValue::Bind("SimulatorImplementationType", StringValue ("ns3::RealtimeSimulatorImpl"));
  GlobalValue::Bind("ChecksumEnabled", BooleanValue (true));

  NS_LOG_UNCOND ("Running simulation in wifi adhoc mode");

  //
  // Create NumNodes
  //
  NS_LOG_UNCOND ("Creating nodes");
  NodeContainer nodes;
  nodes.Create (NumNodes);

  //
  // We're going to use 802.11 A so set up a wifi helper to reflect that.
  //
  NS_LOG_UNCOND ("Creating wifi");
  WifiHelper wifi;
  wifi.SetStandard(WIFI_STANDARD_80211a);
  wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                               "DataMode",
                               StringValue("OfdmRate54Mbps"));

  //
  // No reason for pesky access points, so we'll use an ad-hoc network.
  //
  NS_LOG_UNCOND ("Creating ad hoc wifi mac");
  WifiMacHelper wifiMac;
  wifiMac.SetType ("ns3::AdhocWifiMac");

  //
  // Configure the physcial layer.
  //
  NS_LOG_UNCOND ("Configuring physical layer");
  YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default ();
  YansWifiPhyHelper wifiPhy;
  wifiPhy.SetChannel (wifiChannel.Create ());

  //
  // Install the wireless devices onto our ghost nodes.
  //
  NetDeviceContainer devices = wifi.Install (wifiPhy, wifiMac, nodes);

  InternetStackHelper internetRight;
  internetRight.Install (nodes);

  Ipv4AddressHelper ipv4Right;
  ipv4Right.SetBase ("10.0.0.0", "255.0.0.0");
  Ipv4InterfaceContainer interfacesRight = ipv4Right.Assign (devices);

  //
  // We need location information since we are talking about wifi, so add a
  // constant position to the ghost nodes.
  //
  NS_LOG_UNCOND ("Configuring mobility");
  MobilityHelper mobility;

  mobility.SetPositionAllocator("ns3::UniformDiscPositionAllocator",
                                       "X", ns3::DoubleValue(0.0),
                                       "Y", ns3::DoubleValue(0.0),
                                       "rho", ns3::DoubleValue(distance)); // radius in meters
  mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  mobility.Install(nodes); // Install to the other nodes  

  if (log) // no need to verify if we are not Logging
  {
    // We use stat from POSIX library, which is commonly available in Unix-like environments
    // to see if we have Desktop dir to store output
    struct stat buffer;
    if (!stat(WriteDir.c_str(), &buffer) == 0)
    {
      NS_FATAL_ERROR ("\"results\" folder does not exist");
    }
  }

  /*
  uint16_t port = 9;  // well-known echo port number

  NS_LOG_INFO("Creating Taregt Server Application");
  Ptr<TargetServer> tServer = CreateObject<TargetServer>();
  nodes.Get (0)->AddApplication(tServer);
  tServer->Setup(port, (NumNodes - 1), log, WriteDir);
  tServer->SetStartTime(Seconds(0.));
  tServer->SetStopTime(Seconds(TotalTime));

  Ptr<NetDevice> PtrNetDevice;
  {
    Ptr <Node> PtrNode = nodes.Get (0);
    PtrNetDevice = PtrNode->GetDevice(0);
    Ptr<Ipv4> ipv4 = PtrNode->GetObject<Ipv4> ();
    Ipv4InterfaceAddress iaddr = ipv4->GetAddress (1,0);
    Ipv4Address ipAddr = iaddr.GetLocal ();

    std::cout<<"\n****************************************"
    <<"\nTarget Server IPv4: "<<ipAddr
    <<"\nTarget Server MAC:"<<(PtrNetDevice->GetAddress())
    <<"\n****************************************\n\n";
  }
  */
  Ptr<NetDevice> PtrNetDevice;
  {
    Ptr <Node> PtrNode = nodes.Get (0);
    PtrNetDevice = PtrNode->GetDevice(0);
    Ptr<Ipv4> ipv4 = PtrNode->GetObject<Ipv4> ();
    Ipv4InterfaceAddress iaddr = ipv4->GetAddress (1,0);
    Ipv4Address ipAddr = iaddr.GetLocal ();

    std::cout<<"\n****************************************"
    <<"\nTarget Server IPv4: "<<ipAddr
    <<"\nTarget Server MAC:"<<(PtrNetDevice->GetAddress())
    <<"\n****************************************\n\n";
  }


  //
  // Use the TapBridgeHelper to connect to the pre-configured tap devices for
  // the left side.  We go with "UseLocal" mode since the wifi devices do not
  // support promiscuous mode (because of their natures0.  This is a special
  // case mode that allows us to extend a linux bridge into ns-3 IFF we will
  // only see traffic from one other device on that bridge.  That is the case
  // for this configuration.
  //
  NS_LOG_UNCOND ("Creating tap bridges");
  TapBridgeHelper tapBridge;
  tapBridge.SetAttribute ("Mode", StringValue(mode));

  for (int i = 1; i < NumNodes; i++)
  {
    std::stringstream tapName;
    tapName << "tap-" << TapBaseName << (i+1) ;
    NS_LOG_UNCOND ("Tap bridge = " + tapName.str ());

    tapBridge.SetAttribute ("DeviceName", StringValue (tapName.str ()));
    tapBridge.Install (nodes.Get (i), devices.Get (i));
  }

  // churn
  if (churn != 0)
  {
    bool isChurn[NumNodes + 1];
    for(int i = 0; i <= NumNodes; i++)
    {
        isChurn[i] = false;
    }

    Churn(isChurn, &devices, churn, NoneDevsNodes);
  }

  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

  if (log)
  {
    // dedicated pcap output
    std::string outputf = WriteDir + "/captured_packets_wifi_"+std::to_string(NumNodes-NoneDevsNodes);
    wifiPhy.EnablePcap(outputf, PtrNetDevice, true);
  }

  // iterate our nodes and print their position.
  for (NodeContainer::Iterator j = nodes.Begin(); j != nodes.End(); ++j)
  {
      Ptr<Node> object = *j;
      uint32_t id = object->GetId();
      Ptr<MobilityModel> position = object->GetObject<MobilityModel>();
      NS_ASSERT(position);
      Vector pos = position->GetPosition();
      NS_LOG_UNCOND("node="<<id<<" x=" << pos.x << ", y=" << pos.y << ", z=" << pos.z);
  }

  //
  // Run the simulation for TotalTime seconds to give the user time to play around
  //
  NS_LOG_UNCOND ("\nRunning simulation in wifi mode");
  Simulator::Stop (Seconds (TotalTime));
  Simulator::Run ();
  Simulator::Destroy ();

  return 0;

  // Exit the MPI execution environment
  // MpiInterface::Disable ();
}