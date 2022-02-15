#McAfee ePO raw logs normalization scripts
#Purpose: To convert raw logs from McAfee ePO to CSV. Alternative script to assist security engineer to normalize the logs manually when required.
#Feel free to use it but please don't copyright or claimed it as your own - Sharing is caring <3
#Disclaimer: No sensitive information being provided nor exposed on this script.
#Original Script Author: meowStryker
#Github: https://meowstryker.github.io/

import re

def scriptBanner():
	print("######## McAfee ePO RAW LOG NORMALIZATION SCRIPT ########")
	print("Purpose: To convert raw logs from McAfee ePO to CSV. Alternative script to assist security engineer to normalize the logs manually when required.")
	print("Disclaimer: No sensitive information being provided nor exposed on this script.")
	print("Original Script Author: meowStryker")
	print("Github: https://meowstryker.github.io/\n")

def formula(tag):
    tag = "(?<=<" + tag + ">).*(?=\<\/" + tag + ">)"
    return tag

logTagList = ['MachineName','AgentGUID','IPAddress','OSName','UserName','TimeZoneBias','RawMACAddress','Analyzer','AnalyzerName','AnalyzerVersion','AnalyzerHostName','AnalyzerDATVersion','AnalyzerEngineVersion','EventID','Severity','GMTTime','AnalyzerDetectionMethod','ThreatName','ThreatType','ThreatCategory','ThreatHandled','ThreatActionTaken','ThreatSeverity']

#Machine Info Section
machineNameInLogPattern = re.compile(str(formula(logTagList[0])))
agentGUIDInLogPattern = re.compile(formula(logTagList[1]))
IPAddressInLogPattern = re.compile(formula(logTagList[2]))
OSNameInLogPattern = re.compile(formula(logTagList[3]))
userNameInLogPattern = re.compile(formula(logTagList[4]))
timeZoneBiasInLogPattern = re.compile(formula(logTagList[5]))
rawMACAddressInLogPattern = re.compile(formula(logTagList[6]))

#Software Info Section
##Common Fields Subsection
analyzerInLogPattern = re.compile(formula(logTagList[7]))
analyzerNameInLogPattern = re.compile(formula(logTagList[8]))
analyzerVersionInLogPattern = re.compile(formula(logTagList[9]))
analyzerHostNameInLogPattern = re.compile(formula(logTagList[10]))
analyzerDATVersionInLogPattern = re.compile(formula(logTagList[11]))
analyzerEngineVersionInLogPattern = re.compile(formula(logTagList[12]))

##Event Subsection
eventIDInLogPattern = re.compile(formula(logTagList[13]))
severityInLogPattern = re.compile(formula(logTagList[14]))
GMTTimeInLogPattern = re.compile(formula(logTagList[15]))
analyzerDetectionMethodInLogPattern = re.compile(formula(logTagList[16]))
threatNameInLogPattern = re.compile(formula(logTagList[17]))
threatTypeInLogPattern = re.compile(formula(logTagList[18]))
threatCategoryInLogPattern = re.compile(formula(logTagList[19]))
threatHandledInLogPattern = re.compile(formula(logTagList[20]))
threatActionTakenInLogPattern = re.compile(formula(logTagList[21]))
threatSeverityInLogPattern = re.compile(formula(logTagList[22]))

scriptBanner()
readFile = input("Enter file name: ")
writeFile = input("Enter file name to be saved: ")
writeFile += ".csv"

allmachineNameSet, allagentGUIDSet, allIPAddressSet, allOSNameSet, alluserNameSet, alltimeZoneBiasSet, allrawMACAddressSet, allanalyzerSet, allanalyzerNameSet, allanalyzerVersionSet, allanalyzerHostNameSet, allanalyzerDATVersionSet, allanalyzerEngineVersionSet, alleventIDSet, allseveritySet, allGMTTimeSet, allanalyzerDetectionMethodSet, allthreatNameSet, allthreatTypeSet, allthreatCategorySet, allthreatHandledSet, allthreatActionTakenSet, allthreatSeveritySet = ([] for i in range(23))


with open(writeFile, 'w') as wf:
    with open(readFile, 'r') as rf:
        count = 0                
        Lines = rf.readlines()
        print("Total log lines:","{:,}".format(len(Lines)))
        for line in Lines:
#             print((count+1),"\tLine: ",line)
#             count+=1
            machineNameString, agentGUIDString, IPAddressString, osNameString, userNameString, timeZoneBiasString, rawMACAddressString, analyzerString, analyzerNameString, analyzerVersionString, analyzerHostNameString, analyzerDATVersionString, analyzerEngineVersionString, eventIDString, severityString, GMTTimeString, analyzerDetectionMethodString, threatNameString, threatTypeString, threatCategoryString, threatHandledString, threatActionTakenString, threatSeverityString = ("" for j in range(23))
            
            machineName = machineNameInLogPattern.findall(line) #Grab Machine Name matching pattern in logs
            agentGUID = agentGUIDInLogPattern.findall(line) #Grab Agent GUID matching pattern in logs
            IPAddress = IPAddressInLogPattern.findall(line) #Grab IP Address matching pattern in logs            
            osName = OSNameInLogPattern.findall(line) #Grab OS matching pattern in logs
            userName = userNameInLogPattern.findall(line) #Grab User Name matching pattern in logs
            timeZoneBias = timeZoneBiasInLogPattern.findall(line) #Grab OS matching pattern in logs            
            rawMACAddress = rawMACAddressInLogPattern.findall(line) #Grab raw MAC Address pattern in logs            
            analyzer = analyzerInLogPattern.findall(line) #Grab Analyzer pattern in logs
            analyzerName = analyzerNameInLogPattern.findall(line) #Grab Analyzer Name pattern in logs
            analyzerVersion = analyzerVersionInLogPattern.findall(line) #Grab Analyzer Version pattern in logs
            analyzerHostName = analyzerHostNameInLogPattern.findall(line) #Grab Analyzer Host Name pattern in logs
            analyzerDATVersion = analyzerDATVersionInLogPattern.findall(line) #Grab Analyzer DAT Version pattern in logs
            analyzerEngineVersion = analyzerEngineVersionInLogPattern.findall(line) #Grab Analyzer Engine Version pattern in logs
            eventID = eventIDInLogPattern.findall(line) #Grab Event ID pattern in logs
            severity = severityInLogPattern.findall(line) #Grab Severity pattern in logs
            GMTTime = GMTTimeInLogPattern.findall(line) #Grab GMT Time pattern in logs
            analyzerDetectionMethod = analyzerDetectionMethodInLogPattern.findall(line) #Grab Analyzer Detection Method in logs
            threatName = threatNameInLogPattern.findall(line) #Grab Threat Name Method in logs
            threatType = threatTypeInLogPattern.findall(line) #Grab Threat Type Method in logs
            threatCategory = threatCategoryInLogPattern.findall(line) #Grab Threat Category Method in logs
            threatHandled = threatHandledInLogPattern.findall(line) #Grab Threat Handled Method in logs            
            threatActionTaken = threatActionTakenInLogPattern.findall(line) #Grab Threat Action Taken matching pattern in logs
            threatSeverity = threatSeverityInLogPattern.findall(line) #Grab Threat Severity Taken matching pattern in logs
            
            
            #Put data to apropriate lits if the data exist. Else, put empty strings (for record purpose)            
            if(len(machineName) > 0):
                machineNameString = machineName[0]
                allmachineNameSet.append(machineNameString)
            else:
                 allmachineNameSet.append("")
                 
            if(len(agentGUID) > 0):
                agentGUIDString = agentGUID[0]
                allagentGUIDSet.append(agentGUIDString)
            else:
                 allagentGUIDSet.append("")
                 
            if(len(IPAddress) > 0):
                IPAddressString = IPAddress[0]
                allIPAddressSet.append(IPAddressString)
            else:
                 allIPAddressSet.append("")
                 
            if(len(osName) > 0):
                osNameString = osName[0]
                allOSNameSet.append(osNameString) #Include all OS (duplicate)
            else:
                 allOSNameSet.append("")
                 
            if(len(userName) > 0):
                userNameString = userName[0]
                alluserNameSet.append(userNameString)
            else:
                 alluserNameSet.append("")
                 
            if(len(timeZoneBias) > 0):
                timeZoneBiasString = timeZoneBias[0]
                alltimeZoneBiasSet.append(timeZoneBiasString)
            else:
                 alltimeZoneBiasSet.append("")
                 
            if(len(rawMACAddress) > 0):
                rawMACAddressString = rawMACAddress[0]
                allrawMACAddressSet.append(rawMACAddressString)
            else:
                 allrawMACAddressSet.append("")
            
            if(len(analyzer) > 0):
                analyzerString = analyzer[0]
                allanalyzerSet.append(analyzerString)
            else:
                 allanalyzerSet.append("")
            
            if(len(analyzerName) > 0):
                analyzerNameString = analyzerName[0]
                allanalyzerNameSet.append(analyzerNameString)
            else:
                 allanalyzerNameSet.append("")
            
            if(len(analyzerVersion) > 0):
                analyzerVersionString = analyzerVersion[0]
                allanalyzerVersionSet.append(analyzerVersionString)
            else:
                 allanalyzerVersionSet.append("")
            
            if(len(analyzerHostName) > 0):
                analyzerHostNameString = analyzerHostName[0]
                allanalyzerHostNameSet.append(analyzerHostNameString)
            else:
                 allanalyzerHostNameSet.append("")
            
            if(len(analyzerDATVersion) > 0):
                analyzerDATVersionString = analyzerDATVersion[0]
                allanalyzerDATVersionSet.append(analyzerDATVersionString)
            else:
                 allanalyzerDATVersionSet.append("")                
            
            if(len(analyzerEngineVersion) > 0):
                analyzerEngineVersionString = analyzerEngineVersion[0]
                allanalyzerEngineVersionSet.append(analyzerEngineVersionString)
            else:
                 allanalyzerEngineVersionSet.append("")                 
            
            if(len(eventID) > 0):
                eventIDString = eventID[0]
                alleventIDSet.append(eventIDString)
            else:
                 alleventIDSet.append("")
            
            if(len(severity) > 0):
                severityString = severity[0]
                allseveritySet.append(severityString)
            else:
                 allseveritySet.append("")
            
            if(len(GMTTime) > 0):
                GMTTimeString = GMTTime[0]
                allGMTTimeSet.append(GMTTimeString)
            else:
                 allGMTTimeSet.append("")
            
            if(len(analyzerDetectionMethod) > 0):
                analyzerDetectionMethodString = analyzerDetectionMethod[0]
                allanalyzerDetectionMethodSet.append(analyzerDetectionMethodString)
            else:
                 allanalyzerDetectionMethodSet.append("")
            
            if(len(threatName) > 0):    
                threatNameString = threatName[0]
                allthreatNameSet.append(threatNameString)
            else:
                 allthreatNameSet.append("")
            
            if(len(threatType) > 0):    
                threatTypeString = threatType[0]
                allthreatTypeSet.append(threatTypeString)
            else:
                 allthreatTypeSet.append("")
            
            if(len(threatCategory) > 0):
                threatCategoryString = threatCategory[0]
                allthreatCategorySet.append(threatCategoryString)
            else:
                 allthreatCategorySet.append("")
            
            if(len(threatHandled) > 0):
                threatHandledString = threatHandled[0]
                allthreatHandledSet.append(threatHandledString)
            else:
                 allthreatHandledSet.append("")
            
            if(len(threatActionTaken) > 0):
                threatActionTakenString = threatActionTaken[0]       
                allthreatActionTakenSet.append(threatActionTakenString)
            else:
                 allthreatActionTakenSet.append("")  
            
            if(len(threatSeverity) > 0):
                threatSeverityString = threatSeverity[0]
                allthreatSeveritySet.append(threatSeverityString)
            else:
                 allthreatSeveritySet.append("")   
    
#     START of Writing CSV Header / Labels
    column = 0
    columnSize = len(logTagList)
    while column < columnSize:
        if column < 22:            
            wf.write(logTagList[column])
            wf.write(",")            
        elif column == 22:
            wf.write(logTagList[column])
            wf.write("\n")
        column += 1            
    del column
#     END of Writing CSV Header / Labels
    
#     Start of WRITING Data for each rows
    machineNameSize = len(allmachineNameSet)
    agentGUIDSize = len(allagentGUIDSet)    
    ipAddressSize = len(allIPAddressSet)
    osNameSize = len(allOSNameSet)
    userNameSize = len(alluserNameSet)
    timeZoneBiasSize = len(alltimeZoneBiasSet)
    rawMACAddressSize = len(allrawMACAddressSet)
    analyzerSize = len(allanalyzerSet)
    analyzerNameSize = len(allanalyzerNameSet)
    analyzerVersionSize = len(allanalyzerVersionSet)
    analyzerHostNameSize = len(allanalyzerHostNameSet)
    analyzerDATVersionSize = len(allanalyzerDATVersionSet)
    analyzerEngineVersionSize = len(allanalyzerEngineVersionSet)
    eventIDSize = len(alleventIDSet)
    severitySize = len(allseveritySet)
    GMTTimeSize = len(allGMTTimeSet)
    analyzerDetectionMethodSize = len(allanalyzerDetectionMethodSet)
    threatNameSize = len(allthreatNameSet)
    threatTypeSize = len(allthreatTypeSet)
    threatCategorySize = len(allthreatCategorySet)
    threatHandledSize = len(allthreatHandledSet)    
    threatActionTakenSize = len(allthreatActionTakenSet)
    threatSeveritySize = len(allthreatSeveritySet)
    
#     Check allmachineNameSet size (should be same for all)
    if(machineNameSize == agentGUIDSize == ipAddressSize == osNameSize == userNameSize == timeZoneBiasSize == rawMACAddressSize == analyzerSize == analyzerNameSize == analyzerVersionSize == analyzerHostNameSize == analyzerDATVersionSize ==  analyzerEngineVersionSize == eventIDSize == severitySize == GMTTimeSize == analyzerDetectionMethodSize == threatNameSize == threatTypeSize == threatCategorySize == threatHandledSize == threatActionTakenSize ==  threatSeveritySize):
        print("Verifying data integrity - Success!")
        dataSize = machineNameSize
        print("dataSize:",dataSize)
        rowSize = len(allmachineNameSet)
        allData = [allmachineNameSet, allagentGUIDSet, allIPAddressSet, allOSNameSet, alluserNameSet, alltimeZoneBiasSet, allrawMACAddressSet, allanalyzerSet, allanalyzerNameSet, allanalyzerVersionSet, allanalyzerHostNameSet, allanalyzerDATVersionSet, allanalyzerEngineVersionSet, alleventIDSet, allseveritySet, allGMTTimeSet, allanalyzerDetectionMethodSet, allthreatNameSet, allthreatTypeSet, allthreatCategorySet, allthreatHandledSet, allthreatActionTakenSet, allthreatSeveritySet]
#         Start of WRITING data for each column(s) in the row
        column = 0
        row = 0
        while row < rowSize:
            if column < 22:
                wf.write(allData[column][row] + ",")
                column += 1
            elif column == 22:
                wf.write(allData[column][row] + "\n")
                column = 0
                row += 1
        del column, row
#         END of WRITING data for each column(s) in the row

            
    else:
        print("Verifying data integrity - FAILED!\nRow numbers for data does not match")
    
               
