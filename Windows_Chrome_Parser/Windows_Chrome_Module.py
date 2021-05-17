'''
@author: Saarthik Tannan
@contact: saarthik@gmail.com
'''
# This python autopsy module parse Windows Chrome artifacts. The data is stored into
# an sqlite database which is then imported into the extracted view section of Autopsy.

# Author: Saarthik Tannan
# Contact: saarthik@gmail.com

# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

# Windows Chrome Module to parse the Chrome artifacts
# Version 1.0


# Imports
try:
    import datetime
    
    import jarray
    import inspect
    import os
    from urlparse import urlparse, parse_qs
    
    from java.lang import Class
    from java.lang import System
    from java.sql  import DriverManager, SQLException
    from java.util.logging import Level
    from java.io import File
    
    # Autopsy imports
    from org.sleuthkit.datamodel import SleuthkitCase
    from org.sleuthkit.datamodel import AbstractFile
    from org.sleuthkit.datamodel import ReadContentInputStream
    from org.sleuthkit.datamodel import BlackboardArtifact
    from org.sleuthkit.datamodel import BlackboardAttribute
    from org.sleuthkit.autopsy.ingest import IngestModule
    from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
    from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
    from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
    from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
    from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
    from org.sleuthkit.autopsy.ingest import IngestMessage
    from org.sleuthkit.autopsy.ingest import IngestServices
    from org.sleuthkit.autopsy.ingest import ModuleDataEvent
    from org.sleuthkit.autopsy.coreutils import Logger
    from org.sleuthkit.autopsy.coreutils import PlatformUtil
    from org.sleuthkit.autopsy.casemodule import Case
    from org.sleuthkit.autopsy.casemodule.services import Services
    from org.sleuthkit.autopsy.casemodule.services import FileManager
    from org.sleuthkit.autopsy.datamodel import ContentUtils
    
# Print message if error
except ImportError as e:
    print("Error: ", str(e))

# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the anlaysis.
class ParseWindowsChromeIngestModuleFactory(IngestModuleFactoryAdapter):
    def __init__(self):
        self.settings = None
    
    # Module name
    moduleName = "Parse Windows Chrome"

    
    def getModuleDisplayName(self):
        return self.moduleName

    # Module description
    def getModuleDescription(self):
        return "Parses Windows Chrome"

    def getModuleVersionNumber(self):
        return "1.0"

    # Return true if module wants to get called for each file
    def isDataSourceIngestModuleFactory(self):
        return True

    # Can return null if isDataSourceIngestModuleFactory returns false
    def createDataSourceIngestModule(self, ingestOptions):
        return ParseWindowsChromeIngestModule(self.settings)


# Data source-level ingest module. One gets created per thread
class ParseWindowsChromeIngestModule(DataSourceIngestModule):    
    
    _logger = Logger.getLogger(ParseWindowsChromeIngestModuleFactory.moduleName)
    
    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)
        
    def __init__(self, settings):
        self.context = None
        self.local_settings = settings
        self.ChromeArtifactsList = []
    
    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    # TODO: Add any setup code that you need here.
    def startUp(self, context):
        self.context = context
        
        #self.filesFound = 0

        # Throw an IngestModule.IngestModuleException exception if there was a problem setting up
        # raise IngestModuleException("Oh No!")
        # pass    
      
    # Where the analysis is done.
    # The 'dataSource' object being passed in is of type org.sleuthkit.datamodel.Content.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/interfaceorg_1_1sleuthkit_1_1datamodel_1_1_content.html
    # 'progressBar' is of type org.sleuthkit.autopsy.ingest.DataSourceIngestModuleProgress
    # See: http://sleuthkit.org/autopsy/docs/api-docs/3.1/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_data_source_ingest_module_progress.html
    def process(self, dataSource, progressBar):    
        # We don't know how much work is there yet
        progressBar.switchToIndeterminate()
        self.log(Level.INFO, "Starting process")
        self.log(Level.INFO, "Chrome History and Downloads")
        self.ChromeHistory(dataSource, progressBar)
        self.log(Level.INFO, "Chrome Top Sites")
        self.ChromeTopSites(dataSource, progressBar)
        self.log(Level.INFO, "Ending process")
        
        # Post a message to rhw ingest messages in box
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, 
            "Windows Chrome", "Chrome artifacts have been analyzed")
        IngestServices.getInstance().postMessage(message) 
        
        return IngestModule.ProcessResult.OK
    
    
    def CreateTempDir(self):
        # Create Temp directory
        tempDir = Case.getCurrentCase().getTempDirectory()
        self.log(Level.INFO, "Creating temp directory:  " + tempDir)
        try:
            os.mkdir(tempDir)
            return tempDir
        except:
            self.log(Level.INFO, "temp directory already exists")
            return tempDir
    
    '''  
    def date_from_webkit(self, webkit_timestamp):
        # Convert end_time (chrome webkit time format) to human-readable date & Unix time
        epoch_start = datetime.datetime(1601,1,1)
        delta = datetime.timedelta(microseconds=int(webkit_timestamp))
        time = epoch_start + delta
        return time
    '''   
     
    def ChromeHistory(self, dataSource, progressBar):
        '''
        Parse and save history (urls and downloads) to SQL database, and
        import to the extracted view section of Autopsy
        '''
        try:
            # We don't know how much work there is yet
            progressBar.switchToIndeterminate()
        
            # Set the database to be read
            skCase = Case.getCurrentCase().getSleuthkitCase()
            fileManager = Case.getCurrentCase().getServices().getFileManager()
            
            try:
                try:
                    files = fileManager.findFiles(dataSource, "History", "Users/%/AppData/Local/Google/Chrome/User Data/Default")
                
                except Exception as e:
                    self.log(Level.INFO, "Could not find History file" + e.getMessage())
                    return IngestModule.ProcessResult.OK
                
                fileCount = 0
                
                # Create temp directory
                tempDir = self.CreateTempDir()
                self.log(Level.INFO, "tempDir: " + tempDir)
                
                # Write the Event Log file to temp directory 
                for file in files:
                    # Check if the user cancelled the module
                    if self.context.isJobCancelled():
                        return IngestModule.ProcessResult.OK
                    
                    fileCount += 1
                    self.log(Level.INFO, "filename: " + file.getName())
                    self.log(Level.INFO, "tempDir: " + tempDir)
                    # Save the database to the temp directory
                    lclDbPath = os.path.join(tempDir, file.getName())
                    ContentUtils.writeToFile(file, File(lclDbPath))
                  
                for file in files:
                    if file.getName() == "History":
                        # Check if OS is Windows otherwise stop
                        if not PlatformUtil.isWindowsOS():
                            self.log(Level.INFO, "Not running on Windows so stopping process")
                            return IngestModule.ProcessResult.OK
                            
                        # Open the database using JDBC. Connect to the database
                        lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), "History")
                        Class.forName("org.sqlite.JDBC").newInstance()
                        dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)
                        
                        # Query the urls table in the History database for some of the columns
                        stmt = dbConn.createStatement()
                        history_query = "Select url, title, visit_count FROM urls"
                        self.log(Level.INFO, history_query)
                        resultSet = stmt.executeQuery(history_query)
                        self.log(Level.INFO, history_query)
                        self.log(Level.INFO, "Query History table")
                        
                        # Create the artifacts
                        artName = "TSK_WEB_HISTORY"
                        artIDHist = skCase.getArtifactTypeID(artName)
                        artIDHistEvt = skCase.getArtifactType(artName)
                            
                        # Cycle through each row to create artifacts
                        while resultSet.next():
                            try:
                                art = file.newArtifact(artIDHist)
                                self.log(Level.INFO, "Inserting attribute url")
                                art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL.getTypeID(), ParseWindowsChromeIngestModuleFactory.moduleName, resultSet.getString("url")))
                                self.log(Level.INFO, "Inserting attribute title")
                                art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TITLE.getTypeID(), ParseWindowsChromeIngestModuleFactory.moduleName, resultSet.getString("title")))
                                self.log(Level.INFO, "Inserting attribute visit_count")
                                art.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_VALUE.getTypeID(), ParseWindowsChromeIngestModuleFactory.moduleName, resultSet.getString("visit_count")))             
                                
                                
                            except SQLException as e:
                                self.log(Level.INFO, "Error: " + e.getMessage())
                                
                        # Fire off an event so UI updates and refreshes with the new artifacts
                        IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(ParseWindowsChromeIngestModuleFactory.moduleName, artIDHistEvt, None))
                        #IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(ParseWindowsChromeIngestModuleFactory.moduleName, BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_DOWNLOAD, None))
                        
                        # Query the downloads table in the History database for some of the columns
                        history_query2 = "Select target_path, end_time, tab_url FROM downloads"
                        self.log(Level.INFO, history_query2)
                        resultSet2 = stmt.executeQuery(history_query2)
                        self.log(Level.INFO, history_query2)
                        self.log(Level.INFO, "Query downloads table")
                        
                        # Create the artifacts
                        artName2 = "TSK_WEB_DOWNLOAD"
                        artIDDownloads = skCase.getArtifactTypeID(artName2)
                        artIDDownloadsEvt = skCase.getArtifactType(artName2)
                        
                        while resultSet2.next():
                            try: 
                                art2 = file.newArtifact(artIDDownloads)
                                self.log(Level.INFO, "Inserting attribute target_path")
                                art2.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PATH.getTypeID(), ParseWindowsChromeIngestModuleFactory.moduleName, resultSet2.getString("target_path")))
                                self.log(Level.INFO, "Inserting attribute end_time")
                                art2.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED.getTypeID(), ParseWindowsChromeIngestModuleFactory.moduleName, resultSet2.getInt("end_time")))
                                self.log(Level.INFO, "Inserting attribute tab_url")
                                art2.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL.getTypeID(), ParseWindowsChromeIngestModuleFactory.moduleName, resultSet2.getString("tab_url")))

                            except SQLException as e:
                                self.log(Level.INFO, "Error: " + e.getMessage())
                                #return IngestModule.ProcessResult.OK
                    
                        # Fire off an event so UI updates and refreshes with the new artifacts
                        IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(ParseWindowsChromeIngestModuleFactory.moduleName, artIDDownloadsEvt, None))
                        
                        # Close database and remove the temp directory              
                        stmt.close()
                        dbConn.close()
                        
                                             
            # Log message if an error occurred                
            except Exception as e:
                self.log(Level.INFO, "Error: " + e.getMessage())
                
        # Log message if an error occurred                
        except:
            self.log(Level.INFO, "An error occurred")
                                             
        
    def ChromeTopSites(self, dataSource, progressBar):
        
        '''Parse and save Top Sites to SQL database, and 
        import to the extract view section of Autopsy'''

        try:
            # We don't know how much work there is yet
            progressBar.switchToIndeterminate()
            # Set the database to be read
            
            skCase = Case.getCurrentCase().getSleuthkitCase()
            # self.log(Level.INFO, "Case dir: " + skCase.getCaseDirectory())
            fileManager = Case.getCurrentCase().getServices().getFileManager()

            try:
                try:
                    files = fileManager.findFiles(dataSource, "Top Sites", "Users/%/AppData/Local/Google/Chrome/User Data/Default")
                
                except Exception as e:
                    self.log(Level.INFO, "Could not find Top Sites file" + e.getMessage())
        
                fileCount = 0
                
                # Create temp directory
                tempDir = self.CreateTempDir()
                self.log(Level.INFO, "tempDir: " + tempDir)
                
                # Write the Event Log file to temp directory 
                for file in files:
                    # Check if the user cancelled the module
                    if self.context.isJobCancelled():
                        return IngestModule.ProcessResult.OK
                    
                    fileCount += 1
                    self.log(Level.INFO, "filename: " + file.getName())
                    self.log(Level.INFO, "tempDir: " + tempDir)
                    # Save the database to the temp directory
                    lclDbPath = os.path.join(tempDir, file.getName())
                    ContentUtils.writeToFile(file, File(lclDbPath))
                  
                
                for file in files:
                    if file.getName() == "Top Sites":
                        # Check if OS is Windows otherwise stop
                        if not PlatformUtil.isWindowsOS():
                            self.log(Level.INFO, "Not running on Windows so stopping process")
                            return IngestModule.ProcessResult.OK
                            
                        # Open the database using JDBC
                        # Connect to database
                        lclDbPath = os.path.join(Case.getCurrentCase().getTempDirectory(), "Top Sites")
                        Class.forName("org.sqlite.JDBC").newInstance()
                        dbConn = DriverManager.getConnection("jdbc:sqlite:%s"  % lclDbPath)    
                    
                        # Create the artifacts
                        try:
                            artID_ts = skCase.addArtifactType("TSK_CHROME_TOPSITES", "Chrome Top Sites")
                        
                        except:
                            self.log(Level.INFO, "Attributes creation error: TSK_CHROME_TOPSITES")
                        '''
                        try: 
                            # custom artifact for url_rank
                            attID_url_rank = skCase.addArtifactAttributeType("TSK_URL_RANK", BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_TYPE.VALUE, "URL Rank")
                        # Log message if error
                        except:
                            self.log(Level.INFO, "Attributes creation error: url_rank")
                        '''
                        # Get the artifacts and attributes
                        artID_ts = skCase.getArtifactTypeID("TSK_CHROME_TOPSITES")
                        artID_ts_evt = skCase.getArtifactType("TSK_CHROME_TOPSITES")
                        
                        # attID_url_rank = skCase.getAttributeType("TSK_URL_RANK")
                        
                        # Query the urls table in the History database for some of the columns
                        stmt = dbConn.createStatement()
                        topsites_query = "Select url, url_rank, title FROM top_sites"
                        self.log(Level.INFO, topsites_query)
                        resultSet3 = stmt.executeQuery(topsites_query)
                        self.log(Level.INFO, topsites_query)
                        self.log(Level.INFO, "Query Top Sites database")
                        
                        # Cycle through each row to create artifacts
                        while resultSet3.next():
                            try: 
                                art3 = file.newArtifact(artID_ts)
                                self.log(Level.INFO, "Inserting attribute url")
                                art3.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL.getTypeID(), ParseWindowsChromeIngestModuleFactory.moduleName, resultSet3.getString("url")))
                                self.log(Level.INFO, "Inserting attribute url_rank")
                                #art3.addAttribute(BlackboardAttribute(attID_url_rank, ParseWindowsChromeIngestModuleFactory.moduleName, resultSet3.getInt("url_rank")))
                                art3.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_VALUE.getTypeID(), ParseWindowsChromeIngestModuleFactory.moduleName, resultSet3.getString("url_rank")))
                                self.log(Level.INFO, "Inserting attribute title")
                                art3.addAttribute(BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TITLE.getTypeID(), ParseWindowsChromeIngestModuleFactory.moduleName, resultSet3.getString("title")))
                             
                            except SQLException as e:
                                self.log(Level.INFO, "Error: " + e.getMessage())
                                return IngestModule.ProcessResult.OK                              
          
                        # Fire off an event so UI updates and refreshes with the new artifacts
                        IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(ParseWindowsChromeIngestModuleFactory.moduleName, artID_ts_evt, None))

                        # Close database and remove the temp directory              
                        stmt.close()
                        dbConn.close()
                                             
            # Log message if an error occurred          
            except Exception as e:
                self.log(Level.INFO, "Error: " + e.getMessage())
                
        # Log message if an error occurred 
        except:
            self.log(Level.INFO, "An error occurred")
            
                