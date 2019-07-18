# Trusted RAM on SAML11 

## Overview

This application demonstrates the enhancing security features of the SAML11, which are Arm TrustZone, trusted RAM, and tamper detection. 

## Requirements

### Hardware

* SAML11 Xplained board
* Type A - micro USB cable

### Software

* Atmel Studio
* TeraTerm

### Description

![Trusted RAM use case](https://bitbucket.org/hainguyenprivaterepo/saml11_trustram_tamper/raw/0eb7dc861259cfe906ec88707ce50d41365443c5/Image/TrustRAM.png)

Inside SAML11, there are two running applications which are the secure and nonsecure application. Each of them locates in trusted and non-trusted area respectively. The secure application initializes the TrustRAM, executes the authentication between the two secure elements on the host and remote side, generates a secret key. This secret key is stored in the trusted RAM as a session key for later usage.

![Content of TrustRAM before and after tamper detection](https://bitbucket.org/hainguyenprivaterepo/saml11_trustram_tamper/raw/0eb7dc861259cfe906ec88707ce50d41365443c5/Image/TrustRAM%20content.png)

The non-secure application is initialized by the secure application. Non-secure application is not allowed to call any functions directly from the secure application but through a predefined function table. In this case, it is the function to print the content of the TrustRAM.

When a tamper attempt is detected, the content in the TrustRAM will be automatically erased so the sensitive data is not exposed. 

## How to run the use case

Download the project to your machine

Open the project with Atmel Studio

Compile the project

Start TeraTerm with the following configuration
* Baud: 9600
* Data: 8 bits
* Stop bit: 1 bit
* Parity: none

In Atmel Studio, run the project. 

Press the SW0 button on the SAML11 board to read the content of the trusted RAM

Touch all the pin of the extension EXT1 of the SAML11 board to simulate a tamper attempt. 

Press SW0 again to check the content in the trusted RAM  

## Contact

Quang Hai Nguyen

Field Application Engineer  

Arrow Central Europe GmbH    

qnguyen@arroweurope.com