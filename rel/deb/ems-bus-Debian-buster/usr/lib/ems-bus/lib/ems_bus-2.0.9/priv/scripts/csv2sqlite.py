#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Author: Everton de Vargas Agilar
# ErlangMS Team
# Objective: Convert a csv to a sqlite table
#
#
#
# Requirements to run the service:
#		* Python 3 and sqlite3 installed
#
#
# How to use: 
#
#    $ ./csv2sqlite.py databasename table_name filename delimiter
#
#
#
#
#
## Histórico de modificações do software:
#
# Data       |  Quem           |  Mensagem  
# -----------------------------------------------------------------------------------------------------
# 25/07/2016  Everton Agilar     Release inicial    
# 02/08/2016  Everton Agilar     Importa um CSV mesmo se há linhas inválidas
#
#
#
#
#
#
########################################################################################################


import csv
import sqlite3
import sys
import codecs


class Csv2SqliteGenerator(object):
    """
    Convert a csv to a sqlite table
    """

    def __init__(self, database_name, table_name, file_name, delimiter=';'):
        csv_handle = open(file_name, 'r')
        try:
            self.csv_data = csv.reader(csv_handle, delimiter=delimiter)
            self.conn = sqlite3.connect(database_name)
            self.cursor = self.conn.cursor()
            self.table_name = table_name
            self._drop_table_if_exists()
            for row in self.csv_data:
                if self.csv_data.line_num == 1:
                    self._do_create_table(row)
                    continue
                if len(row) != self.field_count:
                    print("Linha inválida: " + str(self.csv_data.line_num))
                    continue
                row_utf8 = [field.strip() for field in row]
                query = "INSERT INTO %s VALUES (%s)" % (self.table_name, ','.join(['?' for x in row]))
                self.cursor.execute(query, row_utf8)
            self.conn.commit()
            self.conn.close()
        finally:
            csv_handle.close()

    def _drop_table_if_exists(self):
        try:
            self.cursor.execute("DROP TABLE %s" % self.table_name)
        except Exception:
            pass

    def _do_create_table(self, field_names):
        # Remove the BOM if necessary
        FirstColumn = field_names[0]
        if bytes(FirstColumn[0:1], 'utf-8') == b'\xef\xbb\xbf':
            field_names[0] = FirstColumn[1:]
        self.field_count = len(field_names)
        sql = "CREATE TABLE %s" % self.table_name
        query = '%s (%s)' % (sql, ','.join(['%s text' % field_name for field_name in field_names]))
        self.cursor.execute(query)


if __name__ == '__main__':
    print("csv2sqlite - convert csv files to sqlite database")

    # The command should receive all the arguments
    if len(sys.argv) != 5:
        print("How to use: csv2sqlite.py databasename table_name filename delimiter")
        exit(1)

    # Set all variables in parameters
    args = sys.argv[1:]
    database_name = args[0]
    table_name = args[1]
    file_name = args[2]
    delimiter = args[3]

    # Print the variables that will be used
    print("Database name->%s" % database_name)
    print("Table name->%s" % table_name)
    print("File name->%s" % file_name)
    print("Delimiter->%s" % delimiter)

    table = Csv2SqliteGenerator(database_name, table_name, file_name, delimiter)

    print("pronto!")
