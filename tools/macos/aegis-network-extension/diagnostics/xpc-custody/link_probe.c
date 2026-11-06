#include "diagnostic_gate.h"
#include <stddef.h>

int main(void) {
    return aegis_r66_gate_completed(NULL) ? 1 : 0;
}
