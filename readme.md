# Basic JWKS server implementation

This is a basic implementation of a JWKS server using Python with Flask and Cryptography

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Test](#test)
- [Result](#result)

## Installation

This project use Python 3.11.5
To run the server, make sure you have Flask and Cryptography installed on your machine

To install Flask:<br>
**pip install Flask**

To install Cryptography:<br>
**pip install cryptography**

To conduct tests using the provided test file, you need to have Coverage:<br>
**pip install coverage**

## Usage

To run the server simply do:<br>
**python -m server**

## Test

I have written in total 7 test cases for the server. You can see them in test.py
I am using Unittest for testing and Coverage for the report

Running coverage with it not in $PATH:<br>
**python -m coverage run test**<br>
**python -m coverage report** (to see the report)<br>

Running with coverage in $PATH:<br>
**coverage run test**<br>
**coverage report** (to see the report)<br>

## Result

Here you can see screenshots of my tests with my own tests, POST and GET tests using Insomnia, and a blackbox test that you can access<br>
Here: https://github.com/jh125486/CSCE3550/releases

**My own test file:**<br>

![Test case images](./screenshots/coverage_report.PNG)

**POST test using insomnia:**<br>

![POST test images](./screenshots/POST_test.PNG)

**GET test using insomnia:**<br>

![GET test images](./screenshots/GET_test.PNG)

**Blackbox testing:**<br>
I do not know why but when I run the blackbox, I do not see any pop up, the only think I see is this, what the console print out for me
I'm sorry if this is not what needed, I can not figured out why the blackbox just wont show up.
The only guess I can make is that I'm running it on Window and for some reason Window is preventing it
( I did not know that a new version of the black box that fix the window issue was released, this is it properly running, I do not know why the black box is showing 
so many problem when Insomnia testing went find)

![Blackbox test images](./screenshots/Black_box_test.PNG)
