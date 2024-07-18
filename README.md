# Process scanner
A tool that realizes different enumerations in your machine; processes, connections, and system information and users. This version supports Windows and Linux OS.

## Prepare
```
>> git clone https://github.com/TheManuelML/Process-Scanner
>> cd Process-Scanner

>> python3 -m venv venv
>> source venv/bin/activate

>> pip install -r requirements.txt
```

## Run
```
>> python3 scanner.py --help
```

## Options
- -m, --mode   ->  Select the scan mode, check the scanning modes in the --help message.
- -s, --save   ->  Save the output of the scan in a file, required argument: File-name. (Not working)
- -h, --help   ->  Print a help message and exit.
