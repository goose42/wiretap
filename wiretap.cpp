
#include "read_fns.h"

#include <iostream>

int main(int argc,char* argv[])
{
    using std::cout;
    using std::endl;
    FILE *input_file;

    //check if correct number of arguments 
    if (argc != 2) {
        std::cout << "Incorrect method to execute"
            " wiretap." << endl << "Please run wiretap with the following"
            " command:" << endl << "\t./wiretap <pcap dump file name>" <<
            endl;
        return 0;
    }

    input_file = fopen(argv[1], "r"); //open file

    //check if file opens correctly.
    if (input_file == NULL) {
        cout << "Error with opening file, please check the file name" << endl;
        return 0;
    }  

    //once file is opened, pass it into the pcap method to read and make sense of
    cap_file::pcap_read(input_file); 

    fclose(input_file);
    return 0;
}

