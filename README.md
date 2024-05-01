This project introduces a new protocol that sits right after the ethernet frame or is part of the ethernet data directly like the Internet Protocol Layer.

This protocol is named as Dynamically Encrypted Key Exchange Protocol (DEKX) and contains -

i) an ID Field [INTEGER, 1] 

ii) a PASSWORD Field [VARCHAR, 96]

iii) a SALT Field [VARCHAR, 5]

iv) an OFFSET Field [INTEGER, 2]

For ease of reproduction of the code and testing we have changed the Data Link Layer to be as Ethernet, otherwise to run it without Wifi both the server and the key device 
should be capable of running monitor mode and send wlan frames without the need of an access point. To simulate, both the programs can either run on two vms or two raspberry pi's connected to 
an access point. In case of using VM connect in bridged setting. To run monitor mode one needs a special network adapter, we have used the ALFA AWUS036AC adapter. 

The program will run smoothly in two separate kali vms. Try to use an upgraded kali vm so we can use docker in it to start the web app and database using the docker compose file in the server vm.

Once, both the systems are up and running including the docker containers in the servers. One can access the localhost:80 in the server to add a new user, make sure the username contains only 1 digit and
the password can be anything. Then on the key vm, we run the Login.py file first and then go to localhost:5000 and enter the user id that we put in the server as well as the password. If everything went well.
We can move on ahead to running the system. Make sure the server.py file contains the right ip address of the docker environment. It could be localhost or a private ip.

First we run server.py and keep it running, Then we run send.py in the key system. As this is the first interaction, the handshake protocol will be executed where the server shares a salt and an offset with the key
system.

In the later stages of running the program (we run only send.py) the normal key exchange protocol is executed and only the salt is updated from the server.
