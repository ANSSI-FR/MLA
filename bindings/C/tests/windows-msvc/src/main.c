#pragma comment(lib, "mla.lib")

int test_writer();
int test_reader_info();
int test_reader_extract();

int main()
{
   int result = 0;
   result += test_writer();
   result += test_reader_info();
   result += test_reader_extract();
   return result;
}
