#McAfee ePO raw logs normalization scripts (RALN)
#Purpose: To convert raw logs from McAfee ePO to CSV. Alternative script to assist security engineer to normalize the logs manually when required.
#Feel free to use it but please don't copyright or claimed it as your own - Sharing is caring <3
#Disclaimer: No sensitive information being provided nor exposed in this script.
#Original Script Author: meowStryker
#Github: https://meowstryker.github.io/

import re

def scriptBanner():
    print("######## McAfee ePO RAW LOG NORMALIZATION SCRIPT (RALN) ########")
    print("Purpose: To convert raw logs from McAfee ePO to CSV. Alternative script to assist security engineer to normalize the logs manually when required.")
    print("License: GPLv3")
    print("Version: 0.3")
    print("Disclaimer: No sensitive information being provided nor exposed in this script.")
    print("Original Script Author: meowStryker")
    print("Github: https://meowstryker.github.io/\n")

def formula(tag):  #Fine tune the regex
    if (tag == 'AgentGUID'):  #Exclude regex from capturing '{' symbol in the tag data
        tag = "(?<=<" + tag + ">\{).*(?=\}\<\/" + tag + ">)"
    elif (tag == 'AnalyzerDATVersion' or tag == 'AMCoreContentVersion'):    #Exclude regex from capturing the rest when there is dot in the data
        tag = "(?<=<" + tag + ">)[0-9\.]*(?=\<\/" + tag + ">)"
    else:
        tag = "(?<=<" + tag + ">).*(?=\<\/" + tag + ">)"  
    return tag

logTagList = ['MachineName','AgentGUID','IPAddress','OSName','UserName','TimeZoneBias','RawMACAddress','Analyzer','AnalyzerName','AnalyzerVersion','AnalyzerHostName','AnalyzerDATVersion','AnalyzerEngineVersion','EventID','Severity','GMTTime','AnalyzerDetectionMethod','ThreatName','ThreatType','ThreatCategory','ThreatHandled','ThreatActionTaken','ThreatSeverity','SourceHostName','SourceIPV4','SourceProcessName','TargetHostName','TargetUserName','TargetFileName','BladeName','AnalyzerContentCreationDate','AnalyzerGTIQuery','ThreatDetectedOnCreation','TargetName','TargetPath','TargetHash','TargetFileSize','TargetModifyTime','TargetAccessTime','TargetCreateTime','Cleanable','TaskName','FirstAttemptedAction','FirstActionStatus','SecondAttemptedAction','AttackVectorType','DurationBeforeDetection','NaturalLangDescription','AccessRequested','DetectionMessage','AMCoreContentVersion']
columnSize = len(logTagList)
columnInLogPattern = [[] for c in range(columnSize)]

countColumn = 0
while countColumn < columnSize:
    columnInLogPattern[countColumn] = re.compile(str(formula(logTagList[countColumn])))
    countColumn += 1

scriptBanner()
readFile = input("Enter file name: ")
writeFile = input("Enter file name to be saved: ")
writeFile += ".csv"

columnSet = [[] for d in range(columnSize)]

with open(writeFile, 'w') as wf:
    with open(readFile, 'r') as rf:
        count = 0                
        Lines = rf.readlines()
        print("Total log lines:","{:,}".format(len(Lines)))
        print("*Please wait, this will take some time...")       
        
        for line in Lines:
            columnString = [""] * columnSize
            columnVar = [""] * columnSize
            
            columnCount2 = 0
            while columnCount2 < columnSize:
                columnVar[columnCount2] = columnInLogPattern[columnCount2].findall(line)                
                
                if (len(columnVar[columnCount2]) > 0):
                    columnString[columnCount2] = columnVar[columnCount2]
                    columnSet[columnCount2].append(columnString[columnCount2])
                else:
                    columnSet[columnCount2].append("")
                
                columnCount2 += 1
    
#     START of Writing CSV Header / Labels
    column = 0
    columnSize = len(logTagList)
    while column < columnSize:
        if (column < columnSize) and (column != columnSize):
            if column != 0:
                wf.write(",")
                        
            wf.write(logTagList[column])
            column += 1
        else:
            wf.write("\n")          
    del column
#     END of Writing CSV Header / Labels
    
    columnCount3 = 0
    columnSizeCheckStatus = True
    columnVarSize = [[] for g in range(columnSize)]
    while columnCount3 < columnSize:
        columnVarSize[columnCount3] = columnSet[columnCount3]
        if (len(columnVarSize[columnCount3]) != len(columnSet[columnCount3])):
            columnSizeCheckStatus = False
        columnCount3 += 1
    
    print("\ncolumnSizeCheckStatus:",columnSizeCheckStatus)
#     Check all set size (should be same for all)
    if (columnSizeCheckStatus == True):
        print("Verifying data integrity - Success!")
        dataSize = len(columnSet[0])
        print("Processed Log Size:", "{:,}".format(dataSize))
        rowSize = dataSize
        allData = [[] for h in range(columnSize)]
        countColumn5 = 0
        while countColumn5 < columnSize:
            allData[countColumn5] = columnSet[countColumn5]
            countColumn5 += 1
        
#         Start of WRITING data for each column(s) in the row
        column = 0
        row = 0
        while row < rowSize:
            while column < columnSize:
#                 print("column:",column,"\trow:",row,"\tallData[column][row]:",allData[column][row],type(allData[column][row]))     #Debug Info
                if  column != 0:
                    wf.write(",")
                if allData[column][row] != '':
                    wf.write(allData[column][row][0])
                column += 1
            wf.write("\n")
            column = 0
            row += 1
        
        del column, row
        ended = input("Processing completed!\nPress Enter to exit")
        del ended  
    else:
        print("Verifying data integrity - FAILED!\nRow numbers for data does not match")
        ended = input("Processing completed!\nPress Enter to exit")
        del ended
#         END of WRITING data for each column(s) in the row 
    
