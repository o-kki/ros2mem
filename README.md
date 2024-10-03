## ROS2MEM: Memory Forensics Plugin for ROS2 Systems

ROS2MEM is a Volatility3 plugin designed for memory forensics of ROS2 (Robot Operating System 2) based systems. It enables the extraction and analysis of ROS2-specific artifacts from memory dumps. </br></br>
dataset_1 link: https://works.do/G0oBxkq</br>
dataset_2 link: https://works.do/F2Ij1Ky
### Features

- RTPS (Real-Time Publish-Subscribe) pattern detection in memory dumps
- Parsing of network information related to ROS2 communication
- Extraction of ROS2-specific information such as node names, topic names, and parameters
- Analysis of node behaviors based on extracted information
- Payload decoding for RTPS data


### Requirements

- Operating System: Linux (This plugin is designed for and tested on Linux systems only)
- Python version: 3.9 or higher
- Volatility3 framework

### Installation

1. Ensure you have Volatility3 installed. If not, install it first:
   ```
   pip install volatility3
   ```

2. Clone this repository:
   ```
   git clone https://https://github.com/o-kki/ros2mem.git
   ```

3. Move the `ros2mem.py` file to your Volatility3 plugins directory:
   ```
   cp ros2mem/ros2mem.py /path/to/volatility3/volatility3/plugins/linux
   ```

### Usage

1. Run the plugin on a memory dump:
   ```
   python3 vol.py -f /path/to/memory_dump.raw linux.ros2mem.ROS2Mem
   ```

2. The plugin will output discovered ROS2-related information, including:
   - RTPS Protocol details
   - ROS2 node names etc.
   - Topic names etc.
   - Service requests and responses
   - Parameter information

### Example Output

```
Offset: 0x7f1234567890, MAC: 00:11:22:33:44:55 >> 66:77:88:99:aa:bb, IP: 192.168.1.100:12345 >> 192.168.1.101:54321, Payload: "sensor_data"
Offset: 0x7f1234568000, Type: ROS-Topic, /robot/position
Offset: 0x7f1234569000, Type: Request, /robot/set_speed
...
```

### Contact

For any queries or support, please open an issue in this repository or contact [jyki3848@gmail.com].
