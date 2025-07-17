from Evtx.Evtx import Evtx
import shutil
import pyuac
import sys
import re
import traceback
from datetime import datetime
from zoneinfo import ZoneInfo
from prettytable import PrettyTable
class winLogEntry:
    eventDict = {}
    logList = set()
    def __init__(self, recordID, eventID, recordChannel, computerName, process_id, timeCreated):
        try:
            self.recordID      = recordID
            self.eventID       = eventID
            self.recordChannel = recordChannel   
            self.computerName  = computerName
            self.process_id    = process_id
            self.timeCreated   = timeCreated
            logTup = (self.recordID, self.eventID, self.recordChannel, self.computerName, self.process_id, self.timeCreated)
            self.makeEventDict()

            winLogEntry.logList.add(logTup)
        except Exception as e:
            print(e)
    def makeEventDict(self):
        winLogEntry.eventDict[self.eventID] = {"Channel": self.recordChannel}


    @classmethod
    def logEntryReturn(cls):
        return(cls.logList)

    @classmethod
    def eventDictReturn(cls):
        return(cls.eventDict)

class winLogParser:

    def __init__(self):
        pass

    def extract_attribute(self, xml, tag, attribute):
        pattern = f"<{tag}[^>]*\\b{attribute}=\"([^\"]+)\""
        match = re.search(pattern, xml)
        if match:
            return match.group(1)

        return None


    def extract_between(self, xml, start, end):

        start_index = xml.find(start)
        end_index = xml.find(end)
        
        if start_index != -1 and end_index != -1:
            start_close = xml.find(">", start_index)
            #print("xml print", xml[start_close + 1:end_index]) #checker
            return xml[start_close + 1:end_index].strip()

    
    def get_event_id(self, xml):
         
                        
         recordID      = self.extract_between(xml, "<EventRecordID>", "</EventRecordID>")   
         eventID       = self.extract_between(xml, "<EventID", "</EventID>")
         recordChannel = self.extract_between(xml,"<Channel>", "</Channel>")
         computerName  = self.extract_between(xml,"<Computer>", "</Computer>")
         
         process_id = self.extract_attribute(xml, "Execution", "ProcessID")
         thread_id = self.extract_attribute(xml, "Execution", "ThreadID")

         timeCreated = self.extract_attribute(xml, "TimeCreated", "SystemTime")
         dt_utc = datetime.fromisoformat(timeCreated)

         # 2. Convert to local timezone (system local)
         mst = ZoneInfo("MST")
         dt_local = dt_utc.astimezone(mst)
         # 3. Remove timezone info (make naive)
         dt_local_naive = dt_local.replace(tzinfo=None)

         timeCreated = dt_local_naive.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt_local_naive.microsecond // 10000:02d} MST"
         #print(recordID), print(eventID), print(f"ProcessID: {process_id}"), print(f"ThreadID: {thread_id}"), print(timeCreated), print(recordChannel) #checker
         #loginfo = {"Record Channel": recordChannel, "EventID": eventID, "ProcessID": process_id,}
         #logs.winLogDictAdd(recordID, timeCreated, loginfo)
         logEntry = winLogEntry(recordID, eventID, recordChannel, computerName, process_id, timeCreated)
def getEventDescription(self):
    events = winLogEntry.eventDictReturn()
    
    



def pTable(logInfo):
    table = PrettyTable()
    x = 0
    print("Table Creator!")
    userInput = input("Select A for full log print out sorted by time. Select E for all event codes or 0 to quit...")
    if userInput.lower() == "a":
        logListDate = sorted(list(logInfo), key=lambda x: x[5])
        for eachEntry in logListDate:
            x += 1
            table.field_names = ["RecordID", "EventID", "ProcessID", "Channel", "Computer Name", "Time Created"]
            table.add_row([eachEntry[0], eachEntry[1], eachEntry[4], eachEntry[2], eachEntry[3], eachEntry[5]])
        
        print(table)
        print(len(logInfo))
        print("List", len(logListDate))
        print("X count", x)

    elif userInput.lower() == "e":
        table.field_names = ["EventID", "Channel", "Quantity",]
        logListEvent = sorted(list(logInfo), key=lambda x: x[1])
        count={}
        for eachEntry in logListEvent:
            event = eachEntry[1]
            if event in count:
                count[event] += 1
                x+=1
            else:
                count[event] = 1
                x+=1
        for event, quantity in count.items():
            table.add_row([event, eachEntry[2], quantity])
        table.sortby = "Quantity"
        table.reversesort = False
        print(table)
        print(len(logInfo))
        print("Number of rows:", len(table.rows))
        print(x)

def get_dst_path(logFile):
    return rf'D:\LogCopies\{logFile}Copy.evtx'

def getLogFile(userInput):
    logFile = ''
    applicationLogPath = r"C:\Windows\System32\winevt\Logs\Application.evtx"
    securityLogPath    = r"C:\Windows\System32\winevt\Logs\Security.evtx"
    systemLogPath      = r"C:\Windows\System32\winevt\Logs\System.evtx"
    try:
        if userInput == "a":
            logFile = "Application"
            src = applicationLogPath
            dst = get_dst_path(logFile)
            print("Copy of Application Log Created. Path is", dst)
            shutil.copy(src, dst)
            return(dst)

        elif userInput == "s":
            logFile = "Security"
            src = securityLogPath
            dst = get_dst_path(logFile)
            print("Copy of Security Log Created. Path is", dst)
            shutil.copy(src, dst)
            return(dst)

        elif userInput == "y":
            logFile = "System"
            src = systemLogPath
            dst = get_dst_path(logFile)
            print("Copy of System Log Created. Path is", dst)
            shutil.copy(src, dst)
            return(dst)

    except Exception as e:
        print(e)


def logReaderEVTX(logPath):
    
    parser = winLogParser()
    print("Reading Log")
    x = 0
    with Evtx(logPath) as logFile:
        for record in logFile.records():
            #print(record.xml())
            xml = record.xml()
            parsedLog = parser.get_event_id(xml)
            #print("\n",eventID)
            #print(type(eventID))
            #logs.winLogEntry(parsedLog[0], parsedLog[1], parsedLog[2])
           
            x += 1
           

        #print(winLogEntry.logEntryReturn())
        print("X count", x)
        listL = (winLogEntry.logEntryReturn())
        print(len(listL))
        return(winLogEntry.logEntryReturn())
            #logs.getDictLength()

def getAdmin():
    if not pyuac.isUserAdmin():
        print("Re-launching with admin privileges...")
        pyuac.runAsAdmin()
        sys.exit() 
        
        
    else:
        print("Elevated")

def main():
    print("Running main program as admin.") 
    while True:
        try:
            print("\nSelect 'A' for Application Logs\nSelect 'S' for Security Logs\nSelect 'Y' for System Logs")
            userInput = input("\nSelect a Log to Parse or '0' to quit...")
            if userInput.lower()  == "0":
                break

            elif userInput.lower() in ("a", "s", "y"):
                logPath = getLogFile(userInput)
                print(logPath)
                logInfo = logReaderEVTX(logPath)
                #print(logInfo)
                table = pTable(logInfo)
                print(table)
            else:
                print("Not a Valid Option...")
        except Exception as e:
            print(e)
            traceback.print_exc()
if __name__ == "__main__":
    getAdmin()
    print("Admin Granted")
    main()
