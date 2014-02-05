#include <stdio.h>
#include <string.h>

char*  match_str(const char* str, char* begin, char* end){
    char* ptr_test = (char*)str;
    char* ptr_target = begin;
    while (*ptr_test != '\0' && ptr_target != end){
        if (*ptr_test != *ptr_target) return NULL;
        ptr_test   ++;
        ptr_target ++;
    }

    //ptr_test leach the end of string
    if (*ptr_test == '\0')
        return ptr_target;
    //or not
    return NULL;
}


void test_match_str(){
    {
        const char* a = "abc";
        char* b = (char*)"abcdefg";
        char* r = match_str(a, b, b+strlen(b));
        if (r != b + strlen(a)) printf("error on test case 1\n");
    }

    {
        const char* a = "abc";
        char* b = (char*)"a";
        char* r = match_str(a, b, b+strlen(b));
        if (r != NULL) printf("error on test case 2\n");
    }

    {
        const char* a = "abc";
        char* b = (char*)"abc";
        char* r = match_str(a, b, b+strlen(b));
        if (r != b + strlen(a)) printf("error on test case 3\n");
    }

    {
        const char* a = "abc";
        char* b = (char*)"accd";
        char* r = match_str(a, b, b+strlen(b));
        if (r != NULL) printf("error on test case 4\n");
    }
    
    printf("all done\n");
}

int main(int argc, char** argv){
    test_match_str();
    return 0;
}

