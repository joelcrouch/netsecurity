## Making a KALI Virtual Machine Instance

    Installing and configuring a Kali instance on a Windows laptop was relatively painless.  There are two easily accessible methods on Windows 11 (Pro or education).  The first is using WSL and that is just as easy as this:
    ```in admin Powershell
        wsl --install -d kali-linux
    ```
    Assuming WSL is installed and your account has access to the Windows store, that should start up the download and installation of Kali in WSL.  That takes a few minutes.  After the installation is done, run this command in powershell. The powershell instances are all in an admin mode, and i will refer to the commands being run there as 'pw', as if i were running a bash script.

    ```pw
        wsl -list
    ```
    I have both an Ubuntu and a Kali instance, so the result for me was this:
        ```
         wsl --list
            Windows Subsystem for Linux Distributions:
            Ubuntu (Default)
            kali-linux
        
        ```
        I have named my Kali instance kali-linux on WSL, and the Ubuntu just has a generic name.  To open up Kali on windows, run
        ```pw
            wsl -d kali-linux
        ```
        Replace 'kali-linux' with whatever you have named your Kali instance.  
        Use this to install a gui:
        ```bash
            $ sudo apt install 
            $ sudo apt upgrade
            $ sudo apt install -y kali-win-kex
        ```
        and run it: 
        ```bash
            $ kex --win -s
        ```
        Now you have an instance of Kali up and a nice lil gui.

    The second method to get a Kali instance on your Windows laptop is to use hyper-V, which is a type-1 hypervisor that is featured on Windows 11 packages (Pro or education)  There are some work-arounds to get hyper-v working on Windows 10, and they are easily found. See : https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/quick-start/enable-hyper-v  

    My windows instance was all ready configured for hyper-v to work, so i just downloaded and .iso from from an appropriate source, and check-summed the image. 
    Follow these instructions: ( https://dkmcgrath.github.io/courses/netsec/hyper-v.html ) and it should not take too long.  The instructions are for installing a BSD bastion server, but you can just replace BSD references with the appropriate Kali references.  

## Running setup.sh

    In the instructions above there is a setup.sh that is downloaded.  Make sure you change the permissions
    ```bash
        chmod +x setup.sh
    ```
    Also change the git config lines such that they reference you. Change the name and email references to whatever you are using for this project.

    Setup.sh will do a bunch of stuff.  Install python packages thru pip.  This is exciting because Kali doesn't allow it. This script uses .env to get around it.  Take a look at how it works.  You might need to understand how to do that for future references.  Maybe even write a function that you can use do it so you can lazily type less.  Just saying.   
    The script also sets up zsh as your default terminal.  It has a lot more features than native bash. Its cool.  geeks has nice little comparison of bash and zzh: (https://www.geeksforgeeks.org/bash-scripting-difference-between-zsh-and-bash/)

    #### SYSTEM CONFIGURATION

    To get the setup.sh follow these instructions: (https://dkmcgrath.github.io/courses/netsec/linux_setup.html)
    **Make sure you change your git config name and email here in setup.sh before running it.**
    or do this 
    ```bash
        $ sudo apt update
        $ sudo apt upgrade -y
        $ curl -LO https://raw.githubusercontent.com/dkmcgrath/courses/main/netsec/setup.sh
        $ chmod +x setup.sh
        $ ./setup.sh
    ```
    You may have to install 'curl'. (```bash sudo apt install curl```)  Also at the end of the script, it asks you to tar a file that the script downloads.  Unzip it and run it, and you are done.

    ## OUTPUT from ip a s from both VM's

    ![ip a s from WSL-Kali](https://gitlab.cecs.pdx.edu/crouchj/netsec-crouchj/-/blob/main/hw1/wsl-kali-ipas.png)
    ![ip a s from HYPER-V Kali](https://gitlab.cecs.pdx.edu/crouchj/netsec-crouchj/-/blob/main/hw1/kali-ipas-hyperv.png?ref_type=heads)

    ## OUTPUT from both VM's after running setup.sh twice

    ![Kali HyperV after running setup.sh twice](https://gitlab.cecs.pdx.edu/crouchj/netsec-crouchj/-/blob/main/hw1/kali-hyperv-afterrunningsetupsh.png?ref_type=heads)
    ![WSL Kali after running setup.sh twice](https://gitlab.cecs.pdx.edu/crouchj/netsec-crouchj/-/blob/main/hw1/kali-wsl-afterrunningsetupshtwice.png?ref_type=heads)


    
