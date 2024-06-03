#coding: utf-8
import sys

# error handling for incorrect number of argument
if len(sys.argv) < 4:
    print('Error: invalid arguments')
    print('Usage: client resolver_ip resolver_port name timeout')
    sys.exit(1)

#Define connection (socket) parameters
resolverIP = sys.argv[1]
resolverPort = int(sys.argv[2])
requestName = sys.argv[3]
timeout = 0
queryType = 'A'

if len(sys.argv) == 5:
    try:
        timeout = int(sys.argv[4])
    except:
        argument = sys.argv[4].upper()
        if argument == 'MX':
            print('argument is MX')
        elif argument == 'CNAME':
            print('argument is CNAME')
        elif argument == 'NS':
            print('argument is NS')
        elif argument == 'PTR':
            print('argument is PTR')


# error handling for incorrect port number
if resolverPort < 2**10 or resolverPort >= 2**16:
    print('Error: invalid port number')
    sys.exit(1)

# error handling for incorrect IP address
numbersIP = re.findall(r"-?\d+\.?\d*", resolverIP)
if len(numbersIP) != 4:
    print('Error: invalid IP')
    sys.exit(1)

for number in (int(inputNumber) for inputNumber in numbersIP):
    if number < 0 or number > 255:
        print('Error: invalid IP')
        sys.exit(1)

print('successful')
