#!/usr/bin/env python3

import sys
import subprocess
import os
import errno
import signal
import time
import argparse
import datetime
import yaml
import random
import shutil
import getpass

__author__ = 'chepeftw'

numberOfDevsStr = '1'
numberOfOthers = 3 # nodes other than Devs (TServer, IDS, and Attacker)
numberOfNodes = numberOfOthers + int(numberOfDevsStr) # all nodes in the simulatin
emulationTimeStr = '600'
churn = '0'
ns3FileLog = '0'
scenarioSize = '5'
network = 'csma'
jobs = max(1, os.cpu_count() - 1)
nameList = []

baseContainerNameConn = 'myconnmanbox'
baseContainerNameDnsm = 'mydnsmasqbox'
baseContainerNameAtt = 'myattackbox'

writeDirectory = ''
pidsDirectory = "./var/pid/"

ns3Version=''
with open('network/ns3_version') as f:
    ns3Version = str.strip(f.readline())

def main():
    global numberOfDevsStr, \
        emulationTimeStr, \
        churn, \
        ns3FileLog, \
        network, \
        scenarioSize, \
        numberOfNodes, \
        nameList, \
        jobs, \
        writeDirectory, \
        numberOfOthers

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)  # Handle Ctrl+C
    signal.signal(signal.SIGTSTP, signal_handler) # Handle Ctrl+Z
    signal.signal(signal.SIGQUIT, signal_handler) # Handle Ctrl+\

    ###############################
    # n == number of nodes
    # t == simulation time in seconds
    ###############################

    parser = argparse.ArgumentParser(description="DDoSim Implementation.", add_help=True)
    parser.add_argument("operation", action="store", type=str, choices=['create', 'ns3', 'emulation', 'destroy'], help="The name of the operation to perform, options: create, ns3, emulation, destroy")

    parser.add_argument("-d", "--devs", action="store",type=int, help="The number of Devs in the simulation")

    parser.add_argument("-t", "--time", action="store", type=int, help="The time in seconds of NS3 simulation")

    parser.add_argument("-n", "--network", action="store", type=str, choices=['csma', 'wifi'], help="The type of network, options: csma, wifi")

    parser.add_argument("-c", "--churn", action="store", type=str, choices=['0', '1', '2'], help="Enable Nodes churn, options: 0, 1, or 2 ; these options are: no churn, static, or dynamic")

    parser.add_argument("-l", "--log", action="store", type=str, choices=['0', '1', '2'], help="Log from NS3 to File, options: 0, 1, or 2 ; these options are: no log, pcap only, or log pcap and statistics. If log is enabled, the files will be stored in desktop")

    parser.add_argument("-s", "--size", action="store", help="The size in meters of NS3 network simulation")

    parser.add_argument("-j", "--jobs", action="store", type=int, help="The number of parallel jobs")

    parser.add_argument('-v', '--version', action='version', version='%(prog)s 3.0')

    args, unknown = parser.parse_known_args()

    if len(unknown):
        print('\x1b[6;30;41m' + '\nUnknown argument: ' +str(unknown)+ '\x1b[0m')
        parser.print_help()
        sys.exit(2)

    if args.devs:
        numberOfDevsStr = args.devs
    if args.time:
        emulationTimeStr = args.time
    if args.network:
        network = args.network
    if args.churn:
        churn = args.churn
    if args.log:
        ns3FileLog = args.log
    if args.size:
        scenarioSize = args.size
    if args.jobs:
        jobs = int(args.jobs)

    operation = args.operation

    # Display input and output file name passed as the args
    print("\nOperation : %s" % operation)
    print("Number of Devs : %s" % numberOfDevsStr)
    print("Simulation time : %s" % emulationTimeStr)
    print("Network Type : %s" % network)
    print("Churn : %s" % ("no churn" if churn=='0' else "static churn" if churn=='1' else "dynamic churn"))
    print("NS3 File Log : %s" % ("disabled" if ns3FileLog=='0' else "enabled"))

    if network == 'wifi':
        print("Scenario Size (Disk): %s" % (scenarioSize))

    print("\t")
    os.environ["NS3_HOME"] = "./network/ns-allinone-"+ns3Version+"/ns-"+ns3Version

    os.environ["DOCKER_CLI_EXPERIMENTAL"] = "enabled"

    numberOfNodes = int(numberOfDevsStr) + numberOfOthers

    if int(numberOfDevsStr) < 1:
        print("number of Devs should be 1 or more")
        sys.exit(2)

    global base_name
    base_name = "emu"

    for x in range(0, numberOfNodes+1): # we are not using emu0
        nameList.append(base_name + str(x))

    if operation == "create":
        create()
    elif operation == "destroy":
        destroy()
    elif operation == "ns3":
        ns3()
    elif operation == "emulation":
        run_emu()
    else:
        print("Nothing to be done ...")


################################################################################
# handling ()
################################################################################
def check_return_code(rcode, message):
    if rcode == 0:
        print("\nSuccess: %s" % message)
        return

    print("\nError: %s" % message)
    print("")
    print('\x1b[6;30;41m' + 'STOP! Please investigate the previous error(s) and run the command again' + '\x1b[0m')
    destroy()  # Adding this in case something goes wrong, at least we do some cleanup
    sys.exit(2)

def check_return_code_chill(rcode, message):
    if rcode == 0:
        print("\nSuccess: %s" % message)
        return

    print("\nError: %s" % message)
    return

def nodes_in_pid_dir():
    return max([int(name.split(base_name)[1]) if (name.split(base_name)[1]) else 0 for name in os.listdir(pidsDirectory) if len(name.split(base_name)) > 1])

def verify_num_nodes():
    docker_files = 0
    if os.path.exists(pidsDirectory):
        if os.listdir(pidsDirectory):
            docker_files =  nodes_in_pid_dir()
            if docker_files != (numberOfNodes):
                print('Please correct the number of nodes (-n %d) in the command'%(docker_files))
                sys.exit(2)
        else:
            print("Run the 'create' command and try again")
            sys.exit(2)
    else:
        print("Run the 'create' command and try again")
        sys.exit(2)

#https://stackoverflow.com/questions/568271/how-to-check-if-there-exists-a-process-with-a-given-pid-in-python
def check_pid(pid):
    """ Check For the existence of a unix pid. """
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True

def process(command, message = None, code = 2):
    process = subprocess.Popen(command, shell=True ,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    out = process.communicate()[0].decode("utf-8").strip()

    if message is not None:
        out = message

    if code == 0:
        print('\r' + out, end="", flush=True)
    elif code == 1:
        print()
        print('\r' + out, end="", flush=True)
    return process.returncode


################################################################################
# Write Directory ()
################################################################################

def obtain_write_dir():
    global writeDirectory

    writeDirectory = ''

    # Get the current working directory
    current_directory = os.getcwd()
    folder_name = "results"
    writeDirectory = os.path.join(current_directory, folder_name)

    try:
        # Check if the folder already exists
        if not os.path.exists(writeDirectory):
            # Create the new folder
            os.makedirs(writeDirectory)
            print(f"\nFolder '{folder_name}' directory {writeDirectory}\n")

    except PermissionError:
        print(f"\nPermission denied: Unable to create folder at {writeDirectory}")
        sys.exit(2)
    except Exception as e:
        print(f"\nAn error occurred: {e}")
        sys.exit(2)


################################################################################
# Hadnle Inturrupts ()
################################################################################
def signal_handler(signum, frame):
    # Notify the user about the interrupt and perform cleanup
    print("\n\nInterrupt signal received.")

    destroy()

    print("\nExiting...")
    sys.exit(0)

################################################################################
# create ()
################################################################################
def create():
    global numberOfOthers
    print("Creating ...\n")
    docker_files = 0
    if os.path.exists(pidsDirectory):
        if os.listdir(pidsDirectory):
            docker_files =  nodes_in_pid_dir()
            if (docker_files!=0):
                print("There are %d node(s) running. Run the 'destroy' command and try again"%(docker_files))
                return
    else:
        try:
            os.makedirs(pidsDirectory, exist_ok=True)
        except OSError as e:
            if errno.EEXIST != e.errno:
                raise

    #############################
    # First we make sure we are running the latest version of our Ubuntu container

    # ---------------------------------------------
    # ---------------------------------------------
    # make sure to adjust "numberOfOthers" based on
    # the number that you have (other than Devs)
    # ---------------------------------------------
    # ---------------------------------------------

    # TServer
    r_code = subprocess.call("DOCKER_BUILDKIT=1 docker buildx build --platform linux/amd64 -t tserver docker/TServer/.", shell=True)
    check_return_code(r_code, "Building TServer container\n")

    # Attacker
    r_code = subprocess.call("DOCKER_BUILDKIT=1 docker buildx build --platform linux/amd64 -t %s docker/Attacker/." % baseContainerNameAtt, shell=True)
    check_return_code(r_code, "Building attacker container %s\n" % baseContainerNameAtt)

    # IDS
    r_code = subprocess.call("DOCKER_BUILDKIT=1 docker buildx build --platform linux/amd64 -t ids docker/IDS/.", shell=True)
    check_return_code(r_code, "Building IDS container\n")

    # Devs
    r_code = subprocess.call("DOCKER_BUILDKIT=1 docker buildx build --platform linux/amd64 -t %s docker/Devs/." % baseContainerNameDnsm, shell=True)
    check_return_code(r_code, "Building nodes container %s\n" % baseContainerNameDnsm)

    r_code = subprocess.call('[ -d "$NS3_HOME" ]', shell=True)
    if r_code !=0 :
        print("Unable to find NS3 in", (os.environ['NS3_HOME']), ", make sure the 'install.sh' file was executed correctly")
    check_return_code(r_code,"Checking NS3 directory")

    if network == 'wifi':
        r_code = subprocess.call("cd network && bash update.sh tap-wifi-virtual-machine.cc " + ns3Version, shell=True)
    else:
        r_code = subprocess.call("cd network && bash update.sh tap-csma-virtual-machine.cc " + ns3Version, shell=True)

    check_return_code(r_code,"Copying latest ns3 file")

    print("NS3 up to date!")
    print("Go to NS3 folder: cd %s" %(os.environ['NS3_HOME']))

    r_code = subprocess.call("cd $NS3_HOME && ./ns3 build -j {}".format(jobs), shell=True)

    if r_code !=0 :
        print("\nUnable to build NS3 in", (os.environ['NS3_HOME']), ", let's try to reconfigure. Then, try again~")
        r_code = subprocess.call("cd $NS3_HOME && ./ns3 clean && ./ns3 distclean &&./ns3 configure --enable-sudo --disable-examples --disable-tests --disable-python --build-profile=optimized && ./ns3 build -j {}".format(jobs), shell=True)

    check_return_code(r_code,"NS3 BUILD")

    print('NS3 Build finished | Date now: %s' % datetime.datetime.now())

    #############################
    # We run the numberOfNodes of containers.
    # https://docs.docker.com/engine/reference/run/
    # They have to run as privileged (to have access to all host devices, might be unsafe, will check later)
    # By default, Docker containers are "unprivileged" and cannot, for example,
    # run a Docker daemon inside a Docker container. This is because by default a container is not allowed to
    # access any devices, but a "privileged" container is given access to all devices.
    # -dit ... -d run as daemon, -i Keep STDIN open even if not attached, -t Allocate a pseudo-tty
    # --name the name of the container, using emuX
    # Finally the name of our own Ubuntu image.

    dir_path = os.path.dirname(os.path.realpath(__file__))

    # https://github.com/dperson/openvpn-client/issues/75
    acc_status = 0

    # TServer
    acc_status += process('docker run --platform linux/amd64 -v "%s"/docker/videos:/var/www/html/ --restart=always --sysctl net.ipv6.conf.all.disable_ipv6=0 --privileged -dit --net=none --name %s %s' % (dir_path, nameList[1], 'tserver'), None, 1)

    # Attacker
    acc_status = process('docker run --platform linux/amd64 --restart=always --sysctl net.ipv6.conf.all.disable_ipv6=0 --privileged -dit --net=none --name %s %s' % (nameList[2], baseContainerNameAtt), None, 1)

    # IDS
    acc_status += process('docker run --platform linux/amd64 --restart=always --sysctl net.ipv6.conf.all.disable_ipv6=0 --privileged -dit --net=none --name %s %s' % (nameList[3], 'ids'), None, 1)

    # Devs
    for x in range(numberOfOthers + 1, (numberOfNodes + 1)):
        acc_status += process('docker run --platform linux/amd64 -v "%s"/docker/videos:/data/ --restart=always --sysctl net.ipv6.conf.all.disable_ipv6=0 --privileged -dit --net=none --name %s %s' % (dir_path, nameList[x], baseContainerNameDnsm), None, 0)

    # If something went wrong running the docker containers, we panic and exit
    check_return_code(acc_status, "Running docker containers")

    time.sleep(1)
    print('Finished running containers | Date now: %s' % datetime.datetime.now())

    #############################
    # we create the bridges and the tap interfaces for NS3
    # Based on NS3 scripts ... https://www.nsnam.org/docs/release/3.25/doxygen/tap-wifi-virtual-machine_8cc.html
    # But in the source you can find more examples in the same dir.
    acc_status = 0
    for x in range(1, numberOfNodes + 1):
        acc_status += process("bash connections/singleSetup.sh %s" % (nameList[x]), None, 0)

    check_return_code(acc_status, "Creating bridge and tap interface")

    acc_status += process("sudo bash connections/singleEndSetup.sh")
    check_return_code(acc_status, "Finalizing bridges and tap interfaces")

    if not os.path.exists(pidsDirectory):
        try:
            os.makedirs(pidsDirectory)
            check_return_code(0, "Creating pids directory")
        except OSError as e:
            check_return_code(1, e.strerror)

    time.sleep(1)
    print('Finished creating bridges and taps | Date now: %s' % datetime.datetime.now())

    #############################
    # we create the bridges for the docker containers
    # https://docs.docker.com/v1.7/articles/networking/
    acc_status = 0
    for x in range(1, numberOfNodes + 1):
        cmd = ['docker', 'inspect', '--format', "'{{ .State.Pid }}'", nameList[x]]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out, err = p.communicate()
        pid = out[1:-2].strip()

        with open(pidsDirectory + nameList[x], "w") as text_file:
            text_file.write(str(pid, 'utf-8'))

        acc_status += process("bash connections/container.sh %s %s" % (nameList[x], x), "Creating bridge side-int-X and side-ext-X for %s"%(nameList[x]), 0)

    # If something went wrong creating the bridges and tap interfaces, we panic and exit
    check_return_code(acc_status, "Creating all bridge side-int-X and side-ext-X" )
    # Old behaviour, but I got situations where this failed, who knows why and basically stopped everything
    # therefore I changed it to passive, if one fails, who cares but keep on going so the next simulations
    # dont break
    # check_return_code_chill(acc_status, "Creating bridge side-int-X and side-ext-X")

    print('Finished setting up bridges | Date now: %s' % datetime.datetime.now())
    print("Done.")

    return


################################################################################
# end create ()
################################################################################


################################################################################
# ns3 ()
################################################################################
def ns3(code = 0):
    global numberOfOthers
    print("NS3 ...\n")
    docker_files = 0
    verify_num_nodes()

    # IDS setup
    r_code = subprocess.call("sudo modprobe ifb", shell=True)
    check_return_code(r_code, "ifb device to redirect packets")

    r_code = subprocess.call("PID=`docker inspect --format '{{ .State.Pid }}' emu3` && sudo ip netns exec $PID ifconfig eth0 0.0.0.0 promisc up", shell=True)
    check_return_code(r_code, "Promiscuous mode for IDS")

    r_code = subprocess.call("sudo tc qdisc add dev tap-emu3 ingress && sudo tc filter add dev tap-emu3 parent ffff: protocol all u32 match u32 0 0 action mirred egress redirect dev si-emu3", shell=True)
    check_return_code(r_code, "mirror Traffic from 'tap-emu3' to 'si-emu3'")

    r_code = subprocess.call('[ -d "$NS3_HOME" ]', shell=True)
    if r_code !=0 :
        print("Unable to find NS3 in", (os.environ['NS3_HOME']), ", make sure the 'install.sh' file was executed correctly")
    check_return_code(r_code,"Checking NS3 directory")


    if os.path.exists(pidsDirectory + "ns3"):
        with open(pidsDirectory + "ns3", "rt") as in_file:
            text = in_file.read()
            if check_pid(int(text.strip())):
                print('NS3 is still running with pid = ' + text.strip())
                return

    total_emu_time = emulationTimeStr

    obtain_write_dir()

    print('About to start NS3 RUN with total emulation time of %s' % str(total_emu_time))

    tmp = 'cd $NS3_HOME && '
    ns3_cmd = ''
    if network == 'wifi':
        tmp += './ns3 run -j {0} "scratch/tap-vm --NumNodes={1} --TotalTime={2} --TapBaseName=emu '
        tmp += '--DiskDistance={3} --Churn={4} --FileLog={5} --WriteDirectory={6} --NoneDevsNodes={7}"'
        ns3_cmd = tmp.format(jobs, str(numberOfNodes), total_emu_time, scenarioSize, churn, ns3FileLog, writeDirectory, numberOfOthers)
    else:
        tmp += './ns3 run -j {0} "scratch/tap-vm --NumNodes={1} --TotalTime={2} --Churn={3} --FileLog={4} --TapBaseName=emu --WriteDirectory={5} --NoneDevsNodes={6} --AnimationOn=false"'
        ns3_cmd = tmp.format(jobs, str(numberOfNodes), total_emu_time, churn, ns3FileLog, writeDirectory, numberOfOthers)

    print("NS3_HOME=%s && %s"% ((os.environ['NS3_HOME']).strip(), ns3_cmd))

    try:
        p = getpass.getpass(prompt='Sudo password:')
    except Exception as error:
        print('ERROR', error)

    from tempfile import SpooledTemporaryFile as tempfile
    f = tempfile()
    f.write((p+'\n').encode('utf-8'))
    f.seek(0)

    proc1 = subprocess.Popen(ns3_cmd,stdin=f,shell=True)
    f.close()
    time.sleep(10)
    proc1.poll()
    input('\nPress the Enter key to continue...')

    print('proc1 = %s' % proc1.pid)

    with open(pidsDirectory + "ns3", "w") as text_file:
        text_file.write(str(proc1.pid))

    print('Running NS3 in the background | Date now: %s' % datetime.datetime.now())

    if code==1:
        return proc1

    return

################################################################################
# end ns3 ()
################################################################################


################################################################################
# run_emu ()
################################################################################
def run_emu():
    print("RUN SIM ...\n")
    verify_num_nodes()

    print('About to start RUN SIM | Date now: %s' % datetime.datetime.now())
    proc1 = None
    exec_code = 0

    if os.path.exists(pidsDirectory + "ns3"):
        with open(pidsDirectory + "ns3", "rt") as in_file:
            text = in_file.read()
            if check_pid(int(text.strip())):
                print('NS3 is still running with pid = ' + text.strip())
            else:
                print('NS3 is NOT running')
                exec_code = 1
                proc1 = ns3(exec_code)
                time.sleep(5)
    else:
        print('NS3 is NOT running')
        exec_code = 1
        proc1 = ns3(exec_code)
        time.sleep(5)

    print("Restarting containers")
    acc_status = 0
    for x in range(1, numberOfNodes + 1):
        acc_status += process("docker restart -t 0 %s" % nameList[x], None, 0)
    check_return_code_chill(acc_status, "Restarting containers")

    #container_name_list = ""
    #for x in range(0, numberOfNodes):
    #    container_name_list += nameList[x]
    #    container_name_list += " "
    #acc_status = subprocess.call("docker restart -t 0 %s" % container_name_list, shell=True)
    #check_return_code_chill(acc_status, "Restarting containers")

    r_code = 0
    for x in range(1, numberOfNodes + 1):
        if os.path.exists(pidsDirectory + nameList[x]):
            with open(pidsDirectory + nameList[x], "rt") as in_file:
                text = in_file.read()
                r_code = process("sudo rm -rf /var/run/netns/%s" % (text.strip()), "Destroying docker bridges for %s"%(nameList[x]), 0)

        cmd = ['docker', 'inspect', '--format', "'{{ .State.Pid }}'", nameList[x]]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        pid = out[1:-2].strip()

        with open(pidsDirectory + nameList[x], "w") as text_file:
            text_file.write(str(pid, 'utf-8'))

    check_return_code_chill(r_code, "Destroying all docker bridges")

    acc_status = 0
    for x in range(1, numberOfNodes + 1):
        acc_status += process("bash connections/container.sh %s %s" % (nameList[x], x), "Creating new bridge side-int-X and side-ext-X for %s"%(nameList[x]), 0)

    check_return_code_chill(acc_status, "Cleaning old netns and setting up new")

    print('Finished RUN SIM | Date now: %s' % datetime.datetime.now())

    print('Letting the simulation run for %s' % emulationTimeStr)

    if exec_code == 1:
        proc1.communicate() # proc1.wait()
    else:
        if os.path.exists(pidsDirectory + "ns3"):
            with open(pidsDirectory + "ns3", "rt") as in_file:
                text = in_file.read()
                while check_pid(int(text.strip())):
                    time.sleep(5)

    print('Finished RUN SIM 2 | Date now: %s' % datetime.datetime.now())

    return

################################################################################
# end run_emu ()
################################################################################


################################################################################
# destroy ()
################################################################################
def destroy():
    print("Destroying ...\n")
    global numberOfNodes
    if os.path.exists(pidsDirectory + "ns3"):
        with open(pidsDirectory + "ns3", "rt") as in_file:
            text = in_file.read()
            if os.path.exists("/proc/" + text.strip()):
                print("NS3 is running ... killing the NS3 process")
                try:
                    os.killpg(os.getpgid(int(text.strip())), signal.SIGTERM)
                    check_return_code_chill(0, "Killing the NS3 Process")
                except Exception as ex:
                    check_return_code_chill(1, "Killing the NS3 Process\n"+ex)

            r_code = subprocess.call("sudo rm -rf %s" % (pidsDirectory +"ns3"), shell=True)
            check_return_code_chill(r_code, "Removing the NS3 pid file")
            r_code = process("sudo modprobe -r ifb")
    print("DESTROYING ALL CONTAINERS")

    r_code = 0
    for x in range(1, numberOfNodes + 1):
        r_code = process("docker stop %s && docker rm %s" % (nameList[x], nameList[x]), "Destroying container %s"%(nameList[x]), 0)
        check_return_code_chill(r_code, "Destroying container %s"%(nameList[x]))

    # r_containers = subprocess.check_output("docker ps -a -q", shell=True).decode('utf-8')
    # r_code = 0
    # if r_containers:
    #     r_containers = r_containers.strip().replace('\n',' ')
    #     r_code = subprocess.call("docker stop %s && docker rm %s"%(r_containers, r_containers), shell=True)
    #     check_return_code_chill(r_code, "Destroying ALL containers")

    # r_code = process("sudo /etc/init.d/docker restart")

    docker_files = 0
    if os.path.exists(pidsDirectory):
        if os.listdir(pidsDirectory):
            docker_files =  nodes_in_pid_dir()
            if docker_files > numberOfNodes:
                numberOfNodes = docker_files
                nameList.clear()
                for x in range(1, numberOfNodes):
                    nameList.append(base_name + str(x + 1))

    r_code = 0
    for x in range(1, numberOfNodes + 1):
        r_code += process("bash connections/singleDestroy.sh %s" % (nameList[x]), "Destroying bridge and tap interface %s" % (nameList[x]), 0)
    check_return_code_chill(r_code, "Destroying bridge and tap interface")

    r_code = 0
    for x in range(1, numberOfNodes + 1):
        if os.path.exists(pidsDirectory + nameList[x]):
            with open(pidsDirectory + nameList[x], "rt") as in_file:
                text = in_file.read()
                r_code += process("sudo rm -rf /var/run/netns/%s" % (text.strip()), "Destroying docker bridges %s" % (nameList[x]), 0)
    check_return_code_chill(r_code, "Destroying docker bridges")

    r_code = 0
    for x in range(1, numberOfNodes + 1):
        r_code += process("sudo rm -rf %s" % (pidsDirectory + nameList[x]))
    check_return_code_chill(r_code, "Removing pids files")

    if os.path.exists(pidsDirectory):
        try:
            shutil.rmtree(pidsDirectory)
            check_return_code_chill(0, "Removing pids directory")
        except OSError as e:
            check_return_code_chill(1, "Removing pids directory\n"+e.strerror)

    return


################################################################################
# end destroy ()
################################################################################


if __name__ == '__main__':
    main()
