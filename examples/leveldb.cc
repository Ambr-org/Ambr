
/**********************************************************************
 * Copyright (c) 2018 Ambr project
 * Written by kan           
 * Leveldb example                  *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#include <iostream>

#include <leveldb/db.h>

#include <sstream>
#include <string>
using namespace std;


void test_leveldb() {
    // Set up database connection information and open database
    leveldb::DB* db;
    leveldb::Options options;
    options.create_if_missing = true;

    leveldb::Status status = leveldb::DB::Open(options, "./testdb", &db);

    if (false == status.ok()) {
        cerr << "Unable to open/create test database './testdb'" << endl;
        cerr << status.ToString() << endl;
        return;
    }
    
    // Add 256 values to the database
    leveldb::WriteOptions writeOptions;
    for (unsigned int i = 0; i < 256; ++i) {
        ostringstream keyStream;
        keyStream << "Key" << i;
        
        ostringstream valueStream;
        valueStream << "Test data value: " << i;
        
        db->Put(writeOptions, keyStream.str(), valueStream.str());
    }
    
    // Iterate over each item in the database and print them
    leveldb::Iterator* it = db->NewIterator(leveldb::ReadOptions());
    
    for (it->SeekToFirst(); it->Valid(); it->Next()) {
        cout << it->key().ToString() << " : " << it->value().ToString() << endl;
    }
    
    if (false == it->status().ok()) {
        cerr << "An error was found during the scan" << endl;
        cerr << it->status().ToString() << endl; 
    }
    
    delete it;
    
    // Close the database
    delete db;
}

int main() {

    test_leveldb();
    return 0;
}