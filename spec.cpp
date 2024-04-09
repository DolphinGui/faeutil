extern "C" void sink(int);

extern "C" void catcher3() {
  try {
    sink(0);
  } catch (int i) {
    sink(1);
  } catch (float i) {
    sink(2);
  } catch (...) {
    sink(3);
  }
}
