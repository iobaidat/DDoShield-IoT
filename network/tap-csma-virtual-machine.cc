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
//  +----------+                              +----------+
//  | virtual  |                              | virtual  |
//  |  Linux   |                              |  Linux   |
//  |   Host   |                              |   Host   |
//  |          |                              |          |
//  |   eth0   |                              |   eth0   |
//  +----------+                              +----------+
//       |                                         |
//  +----------+                              +----------+
//  |  Linux   |                              |  Linux   |
//  |  Bridge  |                              |  Bridge  |
//  +----------+                              +----------+
//       |                                         |
//  +------------+                          +-------------+
//  | "tap-left" |                          | "tap-right" |
//  +------------+                          +-------------+
//       |           n0               n*           |
//       |       +--------+       +--------+       |
//       +-------|  tap   |       |  tap   |-------+
//               | bridge |       | bridge |
//               +--------+  ...  +--------+
//               |  CSMA  |       |  CSMA  |
//               +--------+       +--------+
//                   |                |
//                   |                |
//                   |                |
//                   ==================
//                        CSMA LAN
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
#include "ns3/tap-bridge-module.h"

#include "ns3/netanim-module.h"

#include "ns3/internet-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/applications-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("TapCsmaVirtualMachineExample");


void
Churn(std::vector<bool>& isChurn, NetDeviceContainer *devs, int churn_lev, int NoneDevsNodes)
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

    Ptr<CsmaNetDevice> curr_csma_netdev = DynamicCast<CsmaNetDevice>((*devs).Get(i));
    if (round_val >= churn_threshold)
    {
      isChurn[i] = true;
      curr_csma_netdev->SetAttribute("SendEnable",(BooleanValue(false)));
      curr_csma_netdev->SetAttribute("ReceiveEnable",(BooleanValue(false)));
    }
    else if (isChurn[i])
    {
      isChurn[i] = false;
      curr_csma_netdev->SetAttribute("SendEnable",(BooleanValue(true)));
      curr_csma_netdev->SetAttribute("ReceiveEnable",(BooleanValue(true)));
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
  NS_LOG_UNCOND("churn nodes #:"<<churn_nodes<<"\n");

  if (churn_lev == 2)
    Simulator::Schedule (dyna_churn_dur, &Churn, isChurn, devs, churn_lev, NoneDevsNodes);
}

int 
main (int argc, char *argv[])
{
  bool AnimationOn = false;
  int NumNodes = 10;
  int NoneDevsNodes = 1;
  double TotalTime = 600.0;
  int churn = 0; // 0 => no churn, 1 => static, 2 => dynamic
  int log = 0;   // 0 => disabled, 1 => log pcap, 2 => log all

  std::string TapBaseName = "emu";

  std::string WriteDir = "";

  LogComponentEnable ("TapCsmaVirtualMachineExample", LOG_LEVEL_ALL); // LOG_LEVEL_DEBUG // LOG_LEVEL_INFO

  CommandLine cmd;
  cmd.AddValue ("NumNodes", "Number of nodes", NumNodes);
  cmd.AddValue ("NoneDevsNodes", "Number of nodes other than Devs", NoneDevsNodes);
  cmd.AddValue ("TotalTime", "Total simulation time", TotalTime);
  cmd.AddValue ("TapBaseName", "Base name for tap interfaces", TapBaseName);
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
  GlobalValue::Bind ("SimulatorImplementationType", StringValue ("ns3::RealtimeSimulatorImpl"));
  GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));

  NS_LOG_UNCOND ("Running simulation in csma mode");

  //
  // Create NumNodes ghost nodes.
  //
  NS_LOG_INFO("Creating nodes");
  NodeContainer nodes;
  nodes.Create (NumNodes);

  //
  // Use a CsmaHelper to get a CSMA channel created, and the needed net 
  // devices installed on both of the nodes.  The data rate and delay for the
  // channel can be set through the command-line parser.  For example,
  //
  // ./waf --run "tap=csma-virtual-machine --ns3::CsmaChannel::DataRate=10000000"
  //

  CsmaHelper csma;
  csma.SetChannelAttribute ("DataRate", StringValue ("100GBps"));

  NetDeviceContainer devices = csma.Install (nodes);

  InternetStackHelper internetRight;
  internetRight.Install (nodes);

  Ipv4AddressHelper ipv4Right;
  ipv4Right.SetBase ("10.0.0.0", "255.0.0.0");
  Ipv4InterfaceContainer interfacesRight = ipv4Right.Assign (devices);

  //
  // Use the TapBridgeHelper to connect to the pre-configured tap devices for 
  // the left side.  We go with "UseBridge" mode since the CSMA devices support
  // promiscuous mode and can therefore make it appear that the bridge is 
  // extended into ns-3.  The install method essentially bridges the specified
  // tap to the specified CSMA device.
  //
  NS_LOG_INFO("Creating tap bridges");
  TapBridgeHelper tapBridge;
  tapBridge.SetAttribute ("Mode", StringValue ("UseBridge"));

  for (int i = 0; i < NumNodes; i++)
  {
    std::stringstream tapName;
    tapName << "tap-" << TapBaseName << (i+1) ;
    NS_LOG_INFO("Tap bridge = " + tapName.str ());

    tapBridge.SetAttribute ("DeviceName", StringValue (tapName.str ()));
    tapBridge.Install (nodes.Get (i), devices.Get (i));  
  }

  // churn
  if (churn != 0)
  {
    std::vector<bool> isChurn(NumNodes + 1);
    for(int i = 0; i <= NumNodes; i++)
    {
        isChurn[i] = false;
    }

    Churn(isChurn, &devices, churn, NoneDevsNodes);
  }

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

  if( AnimationOn )
  {
    NS_LOG_UNCOND ("Activating Animation");
    AnimationInterface anim ("animation.xml"); // Mandatory 
    for (uint32_t i = 0; i < nodes.GetN (); ++i)
      {
        std::stringstream ssi;
        ssi << i;
        anim.UpdateNodeDescription (nodes.Get (i), "Node" + ssi.str()); // Optional
        anim.UpdateNodeColor (nodes.Get (i), 255, 0, 0); // Optional
      }

    anim.EnablePacketMetadata (); // Optional
    // anim.EnableIpv4RouteTracking ("routingtable-wireless.xml", Seconds (0), Seconds (5), Seconds (0.25)); //Optional
    anim.EnableWifiMacCounters (Seconds (0), Seconds (TotalTime)); //Optional
    anim.EnableWifiPhyCounters (Seconds (0), Seconds (TotalTime)); //Optional
  }

  //
  // Run the simulation for TotalTime seconds to give the user time to play around
  //
  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

  if (log)
  {
    // dedicated pcap output location
    std::string outputf = WriteDir + "/captured_packets_csma_"+std::to_string(NumNodes - NoneDevsNodes);
    csma.EnablePcap(outputf, PtrNetDevice, true);
  }

  Simulator::Stop (Seconds (TotalTime));
  Simulator::Run ();
  Simulator::Destroy ();
}