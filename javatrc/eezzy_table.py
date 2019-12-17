import collections
from datetime import date

# ---------------------------------------------------------------------------------
# Define a TTable
# ---------------------------------------------------------------------------------
class TTable(collections.UserList):    
    
    NAVIGATION_POS  = 0
    NAVIGATION_NEXT = 1
    NAVIGATION_PREV = 2
    NAVIGATION_TOP  = 3
    NAVIGATION_LAST = 4    
    
    # ---------------------------------------------------------------------------------
    # ---------------------------------------------------------------------------------
    def __init__(self, aColNames=None, aHeaderStr='', aHeaderDic=dict(), aVisibleEntries=1000):
        super().__init__()
        self.mSortReverse = True
        self.mColsFmt     = list()
        self.mFormat      = {int   :'>{}', str : '{}', float : '>{}.2f', date  : '%A %d. %B %Y', TTable: '<{}'}
        self.mColsName    = ['INX']
        self.mColsWidth   = None
        self.mColsType    = None
        self.mColsFilter  = None
        self.mHeaderDic   = dict()
        self.mHeaderStr   = aHeaderStr
        self.mCurrent     = 0
        self.mVisibleRows = aVisibleEntries
        self.mRowInx      = 0
        self.mSelected    = 0
        self.mParent      = self
        self.mPath        = '0'
        
        if aColNames != None:
            self.mColsName.extend(aColNames)
            
        self.mColsWidth   = [len(x) for x in self.mColsName]
        self.mColsType    = [str    for x in self.mColsName]
        self.mColsFilter  = ['*'    for x in self.mColsName]     
           
        self.mHeaderDic['table_caption'] = aHeaderStr
        self.mHeaderDic['table_prev']    = self.NAVIGATION_PREV 
        self.mHeaderDic['table_next']    = self.NAVIGATION_NEXT
        self.mHeaderDic['table_last']    = self.NAVIGATION_LAST
        self.mHeaderDic['table_top']     = self.NAVIGATION_TOP
        self.mHeaderDic['table_pos']     = self.NAVIGATION_POS
        self.mHeaderDic['table_size']    = 0
        self.mHeaderDic['table_current'] = 0
        
        for xKey, xValue in aHeaderDic.items():
            self.mHeaderDic[xKey] = xValue
        
    # ---------------------------------------------------------------------------------
    # ---------------------------------------------------------------------------------
    def __str__(self):
        return self.mHeaderStr.format(**self.mHeaderDic)

    # ---------------------------------------------------------------------------------
    # ---------------------------------------------------------------------------------
    def __format__(self, format_spec):
        return format(self.mHeaderDic['table_caption'] , format_spec)

    # ---------------------------------------------------------------------------------
    # ---------------------------------------------------------------------------------
    def get_path(self):
        return self.mPath

    # ---------------------------------------------------------------------------------
    # ---------------------------------------------------------------------------------
    def get_header(self):
        self.mHeaderDic['table_size']     = len(self)
        self.mHeaderDic['table_position'] = self.mCurrent
        return self.mHeaderDic        
    
    # ---------------------------------------------------------------------------------
    # ---------------------------------------------------------------------------------
    def setColumns(self, aColNames):
        if len(self.mRows) > 0:            
            return
        self.mColsName    = ['INX']
        self.mColsName.extend(aColNames)
        
        self.mColsWidth   = [len(x) for x in self.mColsName]
        self.mColsType    = [str    for x in self.mColsName]
        self.mColsFilter  = ['*'    for x in self.mColsName]        
       
    # ---------------------------------------------------------------------------------
    # ---------------------------------------------------------------------------------
    def get_columns(self):
        return [self.mColsName]

    def get_columns_names(self):
        return self.mColsName[1:]
    
    # ---------------------------------------------------------------------------------
    # ---------------------------------------------------------------------------------
    def get_columns_type(self):
        return self.mColsType

    # ---------------------------------------------------------------------------------
    # ---------------------------------------------------------------------------------
    def set_columns_type(self, aColsType):
        self.mColsType = aColsType

    # ---------------------------------------------------------------------------------
    # ---------------------------------------------------------------------------------
    def setColFmt(self, aType, aFmt):
        self.mFormat.update(aType, aFmt)
            
    # ---------------------------------------------------------------------------------
    # ---------------------------------------------------------------------------------
    def append(self, aRow):
        if len(aRow) != len(self.mColsName)-1:
            return
               
        aRow.insert(0, self.mRowInx)
        
        for xElem in aRow:
            if isinstance(xElem, TTable):
                xElem.mPath   = '{}-{}'.format(self.mPath, str(self.mRowInx))
                xElem.mParent = self 

        self.mRowInx += 1
        
        if len(self.data) == 0:
            self.mColsType = [type(x) for x in aRow]                
        
        super().append(aRow)
        
        aColsWidth      = [len(str(x)) for x in aRow]
        self.mColsWidth = [max(x)      for x in zip(aColsWidth, self.mColsWidth)] 
    
    # ---------------------------------------------------------------------------------
    # ---------------------------------------------------------------------------------
    def get_parent(self):
        return self.mParent 
        
    # ---------------------------------------------------------------------------------
    # ---------------------------------------------------------------------------------
    def setHeader(self, aHeaderDict):
        self.mHeaderDic.update(aHeaderDict)
    
    # ---------------------------------------------------------------------------------
    # ---------------------------------------------------------------------------------
    def do_select(self, index = 0):
        xSaveInx = int(index)
        
        for xInx, xElem in enumerate(self):
            if xElem[0] == xSaveInx:  
                self.mSelected = xInx
                break            
        
    # ---------------------------------------------------------------------------------
    # ---------------------------------------------------------------------------------
    def do_sort(self, index='0', asc = None):        
        aInx    = min(max(0, int(index)), len(self.mColsName)-1)
        aResult = list()
        if asc == None:
            self.mSortReverse = not self.mSortReverse
        else:
            self.mSortReverse = not asc
        
        if self.mColsType[aInx] == int:
            aResult = sorted(self, key=lambda xRow: int(xRow[aInx]),   reverse=self.mSortReverse)
        elif self.mColsType[aInx] == float:
            aResult = sorted(self, key=lambda xRow: float(xRow[aInx]), reverse=self.mSortReverse)
        else:
            aResult = sorted(self, key=lambda xRow: str(xRow[aInx]),   reverse=self.mSortReverse)
        self.data = aResult

    # ---------------------------------------------------------------------------------
    # ---------------------------------------------------------------------------------
    def get_selected(self, index = -1):
        aInx = int(index)
        
        if len(self) == 0:
            return None
        
        if aInx >= 0:
            self.do_select(aInx)
        
        if isinstance(self.data[self.mSelected][1], TTable):
            return self.data[self.mSelected][1]
        else:
            return self
        
    # ---------------------------------------------------------------------------------
    # ---------------------------------------------------------------------------------
    def printTable(self):
        # print header
        # print columns
        # print rows
        xFmtRow = list()
        for xType, xWidth in zip(self.mColsType, self.mColsWidth):
            if xType in self.mFormat:
                xFmtRow.append(self.mFormat[xType].format(xWidth))
            else:
                xFmtRow.append('{}'.format(xWidth))
        
        if len(self.mHeaderStr) > 0: 
            print('Table = {}'.format( self.mHeaderStr.format(**self.mHeaderDic)))
            xLine = [format(xVal, str(xWidth)) for xVal, xWidth in zip(self.mColsName, self.mColsWidth)]
            print('|-{}-|'.format(' |'.join(xLine)))
        
        xBegInx = self.mCurrent
        xEndInx = min(len(self), self.mCurrent + self.mVisibleRows)
        
        for xRow in self.data[xBegInx:xEndInx]:
            xLine = [format(xVal, xFmt) for xVal, xFmt in zip(xRow, xFmtRow)]
            print('| {} |'.format(' |'.join(xLine)))
        pass
    
    # ---------------------------------------------------------------------------------
    # ---------------------------------------------------------------------------------
    def set_visibleItemCount(self, aVisibleItemCount):
        if int(aVisibleItemCount) > 0:
            self.mVisibleRows = aVisibleItemCount

    # ---------------------------------------------------------------------------------
    # ---------------------------------------------------------------------------------
    def do_navigate(self, where = NAVIGATION_NEXT, pos = 0):
        aInx = int(where)
        
        if aInx   == TTable.NAVIGATION_POS:
            self.mCurrent = max(0, min(int(pos), len(self) - self.mVisibleRows))
        elif aInx == TTable.NAVIGATION_NEXT:
            self.mCurrent = max(0, min(len(self.data) - self.mVisibleRows, self.mCurrent + self.mVisibleRows))
        elif aInx == TTable.NAVIGATION_PREV:
            self.mCurrent = max(0, self.mCurrent - self.mVisibleRows)
        elif aInx == TTable.NAVIGATION_TOP:
            self.mCurrent = 0
        elif aInx == TTable.NAVIGATION_LAST:
            self.mCurrent = max(0, len(self.data) - self.mVisibleRows)
        
        self.mHeaderDic['table_current'] = self.mCurrent 

    # ---------------------------------------------------------------------------------
    # ---------------------------------------------------------------------------------
    def get_rows(self):
        xFmtRow = [ self.mFormat[xType].format(xWidth)  for xType, xWidth in zip(self.mColsType, self.mColsWidth)]
        aLines  = list()
        xBegInx = self.mCurrent 
        xEndInx = min(len(self.data), xBegInx  + self.mVisibleRows)
                
        for xRow in self.data[xBegInx:xEndInx]:
            aLines.append( [format(xVal, xFmt) for xVal, xFmt in zip(xRow, xFmtRow)] )            
        return aLines
    

    # ---------------------------------------------------------------------------------
    # ---------------------------------------------------------------------------------
if __name__ == '__main__':   
    aTable = TTable(['Age', 'Size', 'Name', 'Lastname', 'Birthday'], 'taxonomi of {user}', {'user': 'Albert'})
    aTable.append([50, 1.85, 'Albert',  'Zedlitz', date.today()])
    aTable.append([40, 1.65, 'Bettina', 'Zedlitz', date.today()])
    aTable.do_sort(1)

    