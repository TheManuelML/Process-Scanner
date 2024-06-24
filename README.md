# TCP Connection scanner
Linux script that scans TCP connections through running processes. You can also check for geographical information of each connection. Save the scan in a file.

## Prepare
```
>> git clone https://github.com/TheManuelML/scanTCP
>> cd scanTCP

>> python3 -m venv venv
>> source venv/bin/activate

>> pip install -r requirements.txt
```

## Run
```
>> python3 connScan.py --help
```

## Options
- -g, --ghost    Hide the output of the script, recommended to add the (-s) flag to see the output on the saved file.
- -i, --ip       Show extra information about the IP address, geolocalization.
- -s, --save     Save the output of the scan in a file, required argument: File-name.

## Example
![Example_image](https://github.com/TheManuelML/connectionScanner/assets/82970354/e32ab488-c673-4841-8dc3-a5c3f58f390f)
