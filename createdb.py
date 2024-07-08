import mysql.connector

# Connect to MySQL Server
mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  password=""
)

# Create a cursor object
mycursor = mydb.cursor()

# Execute SQL to create database
mycursor.execute("CREATE DATABASE monitoring_db")

# Verify database creation
mycursor.execute("SHOW DATABASES")

# Print all databases
for db in mycursor:
  print(db)