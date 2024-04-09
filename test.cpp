#include <alloca.h>

struct Guard {
  ~Guard();
};

struct Guard2 {
  ~Guard2();
};

extern "C" void sink(char *);
extern "C" int f() {
  Guard g;
  char a[12]{};
  sink(a);
  return 2;
}
extern "C" int g(int i) {
  Guard2 g;
  char *data = (char *)alloca(i);
  sink(data);
  return f() - 3;
}

extern "C" int o() { return f() - 3; }
extern "C" int p() { return o() - 3; }

extern "C" void catcher() {
  char a[4]{};
  try {
    sink(a);
  } catch (int i) {
    p();
  }
}

int global_var = 12;

extern "C" void catcher2() {
  char a;
  try {
    sink(&a);
    o();
  } catch (int i) {
    sink(&a);
  }
}