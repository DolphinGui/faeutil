extern "C" void sink(int *);

extern "C" void f() {
  int a;
  sink(&a);
}
