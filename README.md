Antivirus ArchShied
---

### Description

ArchShield is an antivirus program designed to protect your system from malware.
The program allows you to scan directories for viruses using a local database
and connection to the open MalwareBazaar database. In case a virus is detected,
ArchShield will offer to delete the infected files.

### Features

- Scan files and directories for virus signatures.
- Compare files with a local database and MalwareBazaar's database via API.
- Delete infected files at the user's request.
- Administration: add new viruses to the database, delete users, view the virus
  list by login.

## Tools

## MalwareBazaar

[MalvareBazaar](https://bazaar.abuse.ch/ "Click here to visit MalvareBazaar 
website.") \
MalwareBazaar is a project from abuse.ch with the goal of sharing malware
samples with the infosec community, AV vendors and threat intelligence
providers.

##### Why MalwareBazaar?

The creator of the project himself, Guido Landgas, will answer this question.

> As many IT-security researchers, I'm heavily using public available information (OSINT) for hunting down new cyber threats. OSINT is a great resource for this threat intelligence! However, I often get confronted with a simple but severe problem: malware samples referenced in blog posts, whitepaper or mentioned on social media like Twitter are usually not easily available. You need to register on gazillion different online anti-virus scanning engines, sandboxes or malware databases in order to finally obtain the malware sample you need for your analysis. And it is getting worse: Some of these platforms come with download restrictions (you can only download a specific number of malware samples per day), some other platforms are available for paying users only. This is a huge pain for me in my daily work, and I'm sure for many other IT-security researchers out there too.

##### MalwareBazaar's tools

MalwareBazaar collects known malicious malware sample, enriches them with
additional intelligence and provides them back to the community - for free! Here
are just some of the features of MalwareBazaar:

- Completely community driven and 100% free for commercial and non-commercial
  usage
- Vetted malware samples only. No benign files. No Adware/PUP/PUA
- Download as many malware samples you like
- Extensive API for automation
- Export of hashes
- Daily malware batches avilable for download
- Additional context about malware samples distributed via email by using
  spamtrap data
- Search for samples by malware family name, fuzzy hashing (like TLSH, imphash,
  etc) and tags

## Python

##### Description

> Don't you hate code that doesn't have the right indentation? Including [indentation] in part of the syntax ensures that all code is correctly indented.

by Guido van Rossum

Python is an interpreted, high-level, general-purpose programming language.
Created by Guido van Rossum and first released in 1991, Python emphasizes code
readability, using indentation to define code blocks. The language supports
multiple programming paradigms, including procedural, object-oriented, and
functional programming.

Python is widely used in various domains such as web development, scientific
computing, artificial intelligence, game development, and more. It has a large
number of libraries and frameworks, making it a powerful tool for solving almost
any task.

##### Benefits of Python

- Ease of Learning: Python has a simple syntax that makes it an excellent choice
  for beginners.
- Scalability: Suitable for both small scripts and large complex applications.
- Cross-platform: Works on most operating systems.
- Large Community: There are plenty of resources, documentation, and community
  support.
- Rich Library Ecosystem: For most tasks, there are ready-made solutions
  available.

##### Useful Resources

[Official Python Website](https://www.python.org/) \
[Python Documentation](https://www.python.org/doc/) \
[PyPI - Python Package Index](https://pypi.org/) \
[PEP 8 - Python Style Guide](https://peps.python.org/pep-0008/)

## PostgreSQL
![PostgreSQL](![PostgreSQL](https://www.postgresqltutorial.com/wp-content/uploads/2012/08/What-is-PostgreSQL.png))
PostgreSQL, often simply referred to as Postgres, is a powerful, open-source
object-relational database management system (ORDBMS) with a strong reputation
for reliability, feature robustness, and performance.

##### Key Features

- ACID Compliance: PostgreSQL fully adheres to the ACID (Atomicity, Consistency,
  Isolation, Durability)
  properties, ensuring reliable transactions and data integrity.
- Advanced Data Types: Includes support for JSON, XML, hstore, and other complex
  data types, making it ideal for a variety of applications.
- Extensibility: PostgreSQL is highly extensible, allowing users to define their
  own data types, operators, and even entire languages for stored procedures.
- Full-Text Search: Built-in full-text search capabilities allow for efficient
  querying of textual data.
- Concurrency: Uses Multi-Version Concurrency Control (MVCC) to handle multiple
  transactions simultaneously without conflicts.
- Standards Compliance: Adheres closely to the SQL standard while also offering
  additional features.
- Extensive Documentation: PostgreSQL has comprehensive and detailed
  documentation available, making it accessible for developers and database
  administrators.

###### Community and Support

PostgreSQL has a large, active community that contributes to its development and
provides support to users:

[PostgreSQL Documentation](https://www.postgresql.org/docs/) \
[PostgreSQL Wiki](https://wiki.postgresql.org/wiki/Main_Page) \
[PostgreSQL Mailing Lists](https://www.postgresql.org/list/) 
---

## Installation


Connecting to the MalwareBazaar API
```
base_url = "https://mb-api.abuse.ch/api/v1/sdad"  
headers = {
    'API-KEY': 'insert_your_API_key'
}  
data = {
    'query': 'get_info',
    'hash': hash_value
} 
```
installing Python \
Windows:
```
py -m pip --version
```
Optionally, create a virtual environment:
```
py -m venv tutorial_env
tutorial_env\Scripts\activate
```
Unix/MacOS:
```
python3 -m pip --version
```
Optionally, create a virtual environment:
```
python3 -m venv tutorial_env
source tutorial_env/bin/activate
```
installing PostgreSQL 
```
pip install psycopg2-binary
```
Database config 'database_config_name.ini' 
```
[database]
host = 127.0.0.1
user = postgres
password = password
db_name = db_name
```
Connection to PostgreDB\n
```
class ConnectionDataBase:
    def __init__(self):
        self.connection = self.get_connection()

    @staticmethod
    def get_connection():

        config = configparser.ConfigParser()
        config.read('database_config_name.ini')

        host = config.get('database', 'host')
        user = config.get('database', 'user')
        password = config.get('database', 'password')
        db_name = config.get('database', 'db_name')

        connection = psycopg2.connect(
            host=host,
            user=user,
            password=password,
            database=db_name
        )
        connection.autocommit = True
        return connection
```
<u>Important!</u>

<u>The program administrator is created when creating the database and nothing else</u> \
<u>The password for the virus archive is 'infected'</u>
