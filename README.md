# Pi.Alert Satellite
A companion script for Pi.Alert, which executes the Pi.Alert scan on an external host and sends the data as encrypted JSON to an existing Pi.Alert instance via a separate API.

As I am still in the test/trial phase, there are still many things that are not possible. From time to time, the things that work are listed in the commits. 
The whole thing is still a prototype or feasibility study and there is no guarantee that the work on this will be completed. For this reason, I will not work on any issues that are still in this prototype phase.

## Concept:

### The satellite:
The satellite performs a scan as a complete Pi.Alert instance could do. The result is extended with meta data (satellite ID, various other data) of the satellite. The data is encrypted with a password (that was created in the Pi.Alert frontend when the satellite was created) and sent to a Pi.Alert API. This is done as a POST call and the data is the encrypted JSON as well as the satellite ID in plain text, also known as the satellite token.

### The API:
The API receives the data and checks whether it is a valid token. If this is the case, an attempt is made to decrypt the data using the satellite's password. Corresponding statuses are returned to the satellite in response to the API call. Once the data has been decrypted, it is stored in the directory `pialert/front/satellites`, with the satellite ID as the file name.

### The Pi.Alert backend:
If data import for satellites is activated, the backend checks whether satellite scans are available during a scan cycle. The IDs can be compared again using the file name and within the json. The data is then entered in the "CurrentScan" table and processed as usual.

### The Pi.Alert frontend:
A satellite is created here. The frontend returns both a generated password and the satellite ID. If necessary, a filter could also be created to filter the devices according to the satellite 

