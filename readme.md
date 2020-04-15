# pyNessus Reporting API

## Allows reporting across multiple nessus scans

### Instructions
Copy nessusconfig.example.py to nessusconfig.py  
Modify to add access keys obtained from nessus as well as hostname/ip and port  
Run with
```
flask run -h 0.0.0.0
```

Test by accessing http://host:port/api/scans/summary and ensure JSON is returned

Data can be ingested into Excel with a query such as the following
```
let
    Source = Json.Document(Web.Contents("http://localhost:5050/api/scans/summary")),
    #"Converted to Table" = Record.ToTable(Source),
    #"Renamed Columns" = Table.RenameColumns(#"Converted to Table",{{"Name", "Scan"}, {"Value", "Hosts"}}),
    #"Duplicated Column" = Table.DuplicateColumn(#"Renamed Columns", "Scan", "Scan - Copy"),
    #"Extracted Text Before Delimiter" = Table.TransformColumns(#"Duplicated Column", {{"Scan - Copy", each Text.BeforeDelimiter(_, "-"), type text}}),
    #"Trimmed Text" = Table.TransformColumns(#"Extracted Text Before Delimiter",{{"Scan - Copy", Text.Trim, type text}}),
    #"Renamed Columns1" = Table.RenameColumns(#"Trimmed Text",{{"Scan - Copy", "Site"}})
in
    #"Renamed Columns1"
```