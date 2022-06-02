**MyCarbonEmissionApp ver. 4.0**

---------------------------------Installation----------------------------------------------

***Unix version***

1) Install python 3 from the oficcial site
2) Install wireshark
3) in the terminal,  write pip install virtualenv
4) Go to the root with 
sudo su
5) After it, create a virtual environement with 
python3 -m venv env
6) Activate it with
source env/bin/activate
7) Install packages from requirements.txt
pip install -r /path/to/requirements.txt


*** Windows version***

1) Install python 3 from the oficcial site
2) Install wireshark
3) in the terminal,  write pip install virtualenv
4) After it, create a virtual environement with 
python -m venv env
5) Activate it with
env\Scripts\activate.bat
6) Install packages from requirements.txt
pip install -r /path/to/requirements.txt



-------------------------------------------Launch the program-------------------------------------

All the steps must be done as a root user or as administrator

1) In the virtualenv run
python3 main.py // In Unix
python main.py //In Windows
2) At the first stage you'll have to enter all the credentials of the user.
3) After it, the capture is started
4) Every hour the program will create a file with the results and send it to the server
5) The program stops only with the KeybordInterruption
For shutting it down, in the terminal use ctr+c
