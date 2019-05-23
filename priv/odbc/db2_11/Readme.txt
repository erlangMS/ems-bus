===================================================
README for IBM Data Server Driver for ODBC and CLI
===================================================

1. Linux or Unix
2. Windows
3. Mac

1. Linux or Unix
================

    1. Create a directory for installation of the IBM Data Server Driver for ODBC and CLI software.

          mkdir $HOME/db2_cli_odbc_driver

    2. Copy the IBM Data Server Driver for ODBC and CLI software (vxx_xx_odbc_cli.tar.gz) into the above directory.

          cp vxx_xx_odbc_cli.tar.gz $HOME/db2_cli_odbc_driver

    3. Extract IBM Data Server Driver for ODBC and CLI.

          gunzip vxx_xx_odbc_cli.tar.gz
          tar -xvf vxx_xx_odbc_cli.tar

    4. Export the following environment variables.

          export DB2_CLI_DRIVER_INSTALL_PATH=$HOME/db2_cli_odbc_driver/odbc_cli/clidriver
          export LD_LIBRARY_PATH=$HOME/db2_cli_odbc_driver/odbc_cli/clidriver/lib
          export LIBPATH=$HOME/db2_cli_odbc_driver/odbc_cli/clidriver/lib
          export PATH=$HOME/db2_cli_odbc_driver/odbc_cli/clidriver/bin:$PATH
          export PATH=$HOME/db2_cli_odbc_driver/odbc_cli/clidriver/adm:$PATH

    5. To connect to DB2 for z/OS Server download the license file db2consv_t.lic and copy to the license folder.

          $HOME/db2_cli_odbc_driver/odbc_cli/clidriver/license

2. Windows
==========

    1. Create a directory for installation of the IBM Data Server Driver for ODBC and CLI software.

          mkdir C:\CDRIVER\

    2. Copy the IBM Data Server Driver for ODBC and CLI software (ibm_data_server_driver_for_odbc_cli.zip) into the above directory.

          cp ibm_data_server_driver_for_odbc_cli.zip C:\CDRIVER\

    3. Extract the IBM Data Server Driver for ODBC and CLI.

    4. Install the IBM Data Server Driver for ODBC and CLI. Navigate to the folder C:\CDRIVER\ibm_data_server_driver_for_odbc_cli\clidriver\bin and
       run the below command.

          db2cli install -setup

    5. The default common application data path will be located under C:\ProgramData\IBM\DB2\C_CDRIVER_ibm_data_server_driver_for_odbc_cli_clidriver.

    6. To connect to DB2 for z/OS Server, download the license file db2consv_t.lic and copy to the license folder.

          C:\CDRIVER\ibm_data_server_driver_for_odbc_cli\clidriver\license

3. Mac
======

    1. Create a directory for installation of the IBM Data Server Driver for ODBC and CLI software.

          mkdir $HOME/db2_cli_odbc_driver

    2. Copy the IBM Data Server Driver for ODBC and CLI software (vxx_xx_odbc_cli.tar.gz) into the above directory.

          cp vxx_xx_odbc_cli.tar.gz $HOME/db2_cli_odbc_driver

    3. Extract IBM Data Server Driver for ODBC and CLI.

          gunzip vxx_xx_odbc_cli.tar.gz
          tar -xvf vxx_xx_odbc_cli.tar

    4. Export the following environment variables.

          export DB2_CLI_DRIVER_INSTALL_PATH=$HOME/db2_cli_odbc_driver/odbc_cli/clidriver
          export DYLD_LIBRARY_PATH=$HOME/db2_cli_odbc_driver/odbc_cli/clidriver/lib
          export LD_LIBRARY_PATH=$HOME/db2_cli_odbc_driver/odbc_cli/clidriver/lib
          export LIBPATH=$HOME/db2_cli_odbc_driver/odbc_cli/clidriver/lib
          export PATH=$HOME/db2_cli_odbc_driver/odbc_cli/clidriver/bin:$PATH
          export PATH=$HOME/db2_cli_odbc_driver/odbc_cli/clidriver/adm:$PATH

5. To connect to DB2 for z/OS Server,download the license file db2consv_t.lic and copy to the license folder.

          $HOME/db2_cli_odbc_driver/odbc_cli/clidriver/license

=============================================================
Configuring and validating the IBM Data Server Driver Package
=============================================================

Testing connectivity to the database
https://www.ibm.com/support/knowledgecenter/en/SSEPGG_11.1.0/com.ibm.swg.im.dbclient.install.doc/doc/t0070358.html

============
Useful Links
============

Supported database application programming interfaces
https://www.ibm.com/support/knowledgecenter/SSEPGG_11.1.0/com.ibm.db2.luw.apdv.gs.doc/doc/c0007011.html

IBM data server driver configuration file
https://www.ibm.com/support/knowledgecenter/SSEPGG_11.1.0/com.ibm.swg.im.dbclient.config.doc/doc/c0054555.html

