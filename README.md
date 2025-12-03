# pytenable-was
Branched from pytenable, brand new code due to Tenable WAS API v2 is not fully documented within the current PyTenable package
this package contains additional utilities that are beyond vulnerabilities and findings within Tenable WAS API v2
this package has extensions that goes beyond the current Tenable WAS API v2
list of scans
age of scans
WAS scan mapping
Allows listing of all Tenable WAS Pre-defined templates
Allows listing of all Tenable WAS User-defined templates
Allows comparison between defined scan templates to an exported format with icons
Extensive command line argument interface
Has functions to export to sqllite3, MS SQL (ensure you choose the correct PYODBC
Does not use any Pytenable components due to this package is faster
includes checks and balances for all kinds of performance
includes adjustable limits, chunksizes
includes HTTP Status Codes to console and logging
standard logging format in .log files
export options to .json and .csv without impact on limits on either
tested with over 50,000 WAS Scans, 1 million vulnerabilities and 978,000 findings
has argument to increase threading depending on underlying operating system

