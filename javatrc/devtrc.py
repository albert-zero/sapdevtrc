#!/usr/bin/python3
'''
Created on 10.11.2017

@author: d025762
'''
import cmd
import sys, io, re
import math
import argparse
import itertools, operator

# from eezzy_table import TTable
# from javatrc.eezzy_table import TTable
from javatrc.eezzy_table import TTable


class TOptions:
    def __init__(self, aArgs):
        self.SORT_DIRECTION_UP   = 2
        self.SORT_DIRECTION_DOWN = 1
        self.SORT_DIRECTION_NONE = 0
                
        self.mInxSec    = [0,0,0,0]
        self.mInxSort   = -1
        self.mSortDir   = self.SORT_DIRECTION_NONE
        self.mStatistic = None
        
        if aArgs == None:
            return
        
        xOptions = aArgs.split()
        
        if '-i' in xOptions:
            self.mInxSec = [0,0,0,0]
            xInx  = xOptions.index('-i')
            xInxLst = list( map(int, xOptions[xInx+1].split(':')) )
            list( map(operator.setitem, [self.mInxSec]*3, [0,1,2], xInxLst) )

        if '-s' in xOptions:
            xInx = xOptions.index('-s')
            self.mSortDir = self.SORT_DIRECTION_UP
            try:
                self.mInxSort = int(xOptions[xInx+1])
            except:
                self.mInxSort = 0

        if '+s' in xOptions:
            xInx = xOptions.index('+s')
            self.mSortDir = self.SORT_DIRECTION_DOWN
            try:
                self.mInxSort = int(xOptions[xInx+1])
            except:
                self.mInxSort = 0

        if '-f' in xOptions:
            xInx = xOptions.index('-f')
            self.mFilter  = int(xOptions[xInx+1])

        if '--cpu' in xOptions:
            self.mStatistic = 'cpu'
            
        if '--depth' in xOptions:
            self.mStatistic = 'depth'
           

# -----------------------------------------------------------------------
# Command line for statistic analysis
# -----------------------------------------------------------------------
class TDevAnalyser(cmd.Cmd):
    aFileName = 'std_server0.out'
    
    # Initialize class properties
    def __init__(self, args=None):
        cmd.Cmd.__init__(self)
        self.intro       = 'Stack Traces Analyser for Developer traces'
        self.prompt      = '(hibroker)> '
        self.file        = None
        self.mDumpList   = []
        self.mSortedKeys = []
        self.mHeader     = {'actual_file' : 'Thread Dumps', 'user-text' : 'TEXT', 'action': 'http://localhost:8080'}
        self.mTblRoot    = TTable(['Root'],     'Collected Sections')
        self.mErrors     = TTable(['Errors'])
        self.mTblCurrent = self.mTblRoot
                
    def get_header(self): 
        return self.mHeader
    
    def get_errors(self):        
        return self.mErrors
    
    # Collect one thread
    def readStack(self, aFile, aInfo):                
        aPrefix  = ""
        xNewLine = '\n'

        if '\r\n' in aInfo:
            xNewLine = '\r\n'                
        
        if aInfo.startswith('J'):
            aInfo   = aInfo[3:-len(xNewLine)]
            aPrefix = 'J  ' 
        else:
            aInfo   = aInfo[:-len(xNewLine)]
            
        aTblDump   = TTable(['Thread', 'CPU', 'Depth'], aInfo)
        xRegCpu    = re.compile('cpu=(\d+.\d+)')
        xRegName   = re.compile('^{}"([-.#:@\[\]\w+ /]+)"'.format(aPrefix))
        xRegMethod = re.compile('^{}(\s+)at'.format(aPrefix))
        
        for aLine in aFile:
            if isinstance(aLine, bytes):
                aLine = aLine.decode('utf-8')

            if aLine == "{}{}".format(aPrefix, xNewLine):
                continue
            
            xThreadName = xRegName.search(aLine)
            xThreadCpu  = xRegCpu.search(aLine)
            
            if aLine.startswith('{}Monitors'.format(aPrefix)):
                break

            if xThreadName == None: 
                continue                
            
            if xThreadCpu == None:
                aLine = aFile.readline()
                aLine = aFile.readline()
                xThreadCpu = xRegCpu.search(aLine.decode('utf-8'))
                
            aTblThread = TTable(['Method'], xThreadName.group(1))

            for aLine in aFile:  
                if isinstance(aLine, bytes):
                    aLine = aLine.decode('utf-8')
                                                   
                if aLine == "{}{}".format(aPrefix, xNewLine):
                    break

                xRes = xRegMethod.search(aLine)
                if xRes != None:
                    aTblThread.append([aLine[len(xRes.group(0)):-len(xNewLine)]])
            try:
                xCpuVal = xThreadCpu.group(1).replace(',','.')            
                aTblDump.append([aTblThread, float(xCpuVal), len(aTblThread)])
            except AttributeError:
                aTblDump.append([aTblThread, 0.0, len(aTblThread)])
        return aTblDump

    # Read a developer trace file         
    def get_files(self, file = None, filename = 'dev_server0'):
        'collect the stack traces in a file'
        aSecCount      = 0
        self.aFileName = filename
        aTblSection    = None
        aFile          = file
        
        if file == None:
            return
        
        self.mHeader['actual_file'] = filename
        self.mTblRoot    = TTable(['Root'], 'RootTable')
        self.mTblCurrent = self.mTblRoot
        
        for aLine in aFile:
            if isinstance(aLine, bytes):
                aLine = aLine.decode('utf-8')
                
            if aLine.startswith('stdout/stderr redirect') or aLine.startswith('trc file:'):
                # self.get_statistic(aTblSection)
                # Create a new section                    
                aTblSection  =  TTable(['Collections'], 'Section {}'.format(len(self.mTblRoot) + 1))
                self.mTblRoot.append([aTblSection])
                            
            if aTblSection == None:
                continue            
            
            if aLine.startswith('J  Thread dump triggered') or aLine.startswith('Thread dump triggered') or aLine.startswith('Full thread dump'):
                aStackDump = self.readStack(aFile, aLine)
                aTblSection.append([aStackDump])
        
        for xInx in range( len(self.mTblRoot) ):
            self.calculate_statistic( self.mTblRoot.get_selected(xInx) ) 

        # self.get_statistic(aTblSection)
        # return self.mTblRoot
    
    def get_condensed(self, aArgs):
        xOptions     = TOptions(aArgs)
        xTblFiltered = TTable(['Name', 'Delta-{}'.format(xOptions.mStatistic)])
        xTable       = self.mTblSection[xOptions.mInxSec][1]            
        xTable       = xTable[xOptions.mInxDmp][1]
        
        for xRow in xTable:
            xMax = max( [abs(y - x) for x, y in zip(xRow[2:], xRow[3:])] )
            xTblFiltered.append([xRow[1], xMax])

        if xOptions.mInxSort > 0:
            xTblFiltered.sort(xOptions.mInxSort)
        return xTblFiltered
          
    def get_sorted(self, args=None, table=None):
        if table == None:
            return None
        
        xOptions     = TOptions(args)
        if xOptions.mSortDir == xOptions.SORT_DIRECTION_NONE:
            return table
        
        table.do_sort(xOptions.mInxSort)
        return table
      
    def get_filtered(self, args=None, table=None):
        if table == None:
            return None
        
        xOptions     = TOptions(args)
        aTblFiltered = TTable(table.get_column())
        aParser      = list()
        
        for xFilter in xOptions.mFilter:
            if xFilter != None:
                aParser.append(re.compile(xFilter))
            else:
                aParser.append(None)
                       
        for xRow in table:
            for xParser, xElem in zip(aParser, xRow):
                if xParser == None:
                    continue
                xRes = xParser.search(xElem)
                if xRes == None:
                    break
                
            if xRes != None:
                aTblFiltered.append(xRow)
                
        return self.get_sorted(self, args, aTblFiltered)

    
    # Return the list of sections
    def get_sections(self, args=None):
        xTable = None
        try:
            xOptions = TOptions(args)
            xTable   = self.mTblRoot
            xTable.do_select(xOptions.mInxSec[0])
        except AttributeError:
            return None
        
        self.mTblCurrent = xTable 
        return xTable

    # Return the list of dumps within a section
    def get_dumps(self, args=None):
        xTable = None
        try :
            xOptions = TOptions(args)
            xTable   = self.get_sections(args)
            xTable   = xTable.get_selected()
            xTable.do_select(xOptions.mInxSec[1])
        except AttributeError:
            return None
        
        self.mTblCurrent = xTable 
        return xTable

    # Return the list of threads in a dump
    def get_threads(self, args=None):
        xTable = None
        try :
            xOptions = TOptions(args)
            xTable   = self.get_dumps(args)
            xTable   = xTable.get_selected()
            xTable.do_select(xOptions.mInxSec[2])
        except AttributeError:
            return None
        
        self.mTblCurrent  = xTable 
        return xTable
            
    # Return the list of methods for a thread    
    def get_trace(self, args = None):
        xTable = None
        try :
            xOptions  = TOptions(args)
            xTable    = self.get_threads()
            xTable   = xTable.get_selected()
        except AttributeError:
            return None
        
        self.mTblCurrent  = xTable 
        return xTable        
 
    def get_selected(self, index = -1):
        aInx = int(index)
        if aInx == -1:
            return self.mTblCurrent        
        aSelected = self.mTblCurrent.get_selected(aInx)
        if aSelected != None:
            self.mTblCurrent = aSelected
        return self.mTblCurrent

    def get_parent(self):
        self.mTblCurrent = self.mTblCurrent.get_parent()
       
    def get_current(self):
        return self.mTblCurrent

    def calculate_statistic(self, xSectionTable):
        if xSectionTable == None:
            return
           
        aDictCPU    = dict()
        aDictDepth  = dict()
        
        
        for xInxDumps in range(len(xSectionTable)):
            xDumps   = xSectionTable.get_selected(xInxDumps)
            
            for xRow in xDumps:
                xInx, xName, xCpu, xDepth = xRow
                
                if aDictCPU.get(str(xName)) == None:
                    xList = [xName] + [float(0) for x in range(len(xSectionTable))]
                    aDictCPU[str(xName)] = xList
                
                xList = aDictCPU.get(str(xName))
                xList[xInxDumps+1] = float(xCpu) 

                if aDictDepth.get(str(xName)) == None:
                    xList = [xName] + [0 for x in range(len(xSectionTable))]
                    aDictDepth[str(xName)] = xList
                    
                xList = aDictDepth.get(str(xName))
                xList[xInxDumps+1] = int(xDepth)                
        
            
        xColNames   = ['ThreadName'] + ['CPU-{}'.format(x) for x in range(len(xSectionTable))] + ['Delta']
        xCpuTable   = TTable(xColNames, aHeaderStr="Statistic CPU")            
            
        xColNames   = ['ThreadName'] + ['Depth-{}'.format(x) for x in range(len(xSectionTable))] + ['Delta']
        xDepthTable = TTable(xColNames, aHeaderStr="Statistic Depth")

        for xValues in aDictCPU.values():
            xValues.append(max([abs(x-y) for x, y in zip(xValues[1:], xValues[2:])]))
            xCpuTable.append(xValues)

        for xValues in aDictDepth.values():
            xValues.append(max([abs(x-y) for x, y in zip(xValues[1:], xValues[2:])]))
            xDepthTable.append(xValues)
            
        xSectionTable.append([xCpuTable])
        xSectionTable.append([xDepthTable])
        
    def get_statistic(self, args = None):
        xOptions      = TOptions(args)
        xSectionTable = self.mTblRoot.get_selected()
        
        if xOptions.mStatistic == 'cpu':
            return self.get_sorted( args=args, table=xSectionTable[-2][1] )
        elif xOptions.mStatistic == 'depth':
            return self.get_sorted( args=args, table=xSectionTable[-1][1] )
        else:
            return None
                     
                        
    def get_statistic_depth(self, args = None):
        xOptions    = TOptions(args)
        xInxStat    = 0
        aCollect    = dict()
        aInx        = 0
        
        if xOptions.mStatistic == 'cpu':
            xInxStat = 0
        elif xOptions.mStatistic == 'depth':
            xInxStat = 1
        else:
            return None

        xTableSec = self.get_traces(args)
        xNrDumps  = len(xTableSec)-2
                        
        xTable   = self.get_dumps(args)
        if xTable == None:
            return None
                
        if len(xTable) == 0:        
            for xRowDump in xTableSec[2:]:
                aInx = 0
                for xRowMethod in xRowDump[1]:
                    xInx, xName, xCpu, xDepth = xRowMethod
                    xLst        = aCollect.setdefault(xName, [0 for x in range(xNrDumps)])
                    xLst[aInx]  = xRowMethod[2+xInxStat]
                    aInx       += 1

            for xKey, xVal in aCollect.items():
                xTable.append(xVal + [xKey])
                        
        return self.get_sorted(args, xTable)  
          
    def do_read(self, aArgs):
        """Reads a developer trace file: 
        std_server0.out or dev_server0 """
        aArgsList  = aArgs.split()        
        self.get_files(open(aArgsList[0], 'rb'))
        
        self.mTblRoot.printTable()
                        
    def do_detail(self, aArgs):
        xTable = self.mTblCurrent.get_selected()
        if xTable != None:
            xTable.printTable()
        
        
    def do_show(self, aArgs):
        """Shows the traces for sections
        show sections  [options] 
        show dumps     [options] -i <inx section> 
        show threads   [options] -i <inx section>:<inx dump>   
        show trace     [options] -i <inx section>:<inx dump>:<inx thread>
        show statistic [options] -i <inx section> [--cpu | --depth]
        
        Options:
        -s <inx column> : sort down
        +s <inx column> : sort up
        -f filter as a regular expression for each row
        """
        xOptions = TOptions(aArgs)

        aDetail  = aArgs.split()[0]

        if aDetail == 'sections':
            xTable = self.get_sections(aArgs)
            if xTable != None:
                xTable.printTable()
            return

        if aDetail == 'dumps':
            xTable = self.get_dumps(aArgs)
            if xTable != None:
                xTable.printTable()
            return
        
        if aDetail == 'threads':
            xTable = self.get_threads(aArgs)
            if xTable != None:
                xTable.printTable()
            return
        
        if aDetail == 'trace':
            xTable = self.get_trace(aArgs)
            if xTable != None:
                xTable.printTable()
            return

        if aDetail == 'statistic':
            xTable = self.get_statistic(aArgs)
            if xTable != None:
                xTable.printTable()
            return

                        
    def do_exit(self, arg):
        'leave program or so'
        sys.exit()

# Main entry point
if __name__ == '__main__':    
    import os, select

    parser = argparse.ArgumentParser(description='HiBroker interface')
    parser.add_argument('-file', dest='file', action='store', help='developer trace file')
    parser.add_argument('-pipe', dest='mode', action='store_const', const='pipe', default='cmd', help='switch to pipe mode')

    aShell       = TDevAnalyser()
    aArgs        = parser.parse_args()       
    aShell.mFile = aArgs.file
        
    if aShell.mFile != None:
        aShell.do_read([aShell.mFile, 1])
    aShell.cmdloop()
    
    