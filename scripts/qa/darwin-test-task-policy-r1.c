/* Test-only self-task policy witness, loaded after exec into one Rust test ELF. */
#include <errno.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach/task_policy.h>
#include <mach-o/dyld.h>
#include <pthread/qos.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

struct facts {
    int background, nice, role, latency, throughput, qos;
};

static void refuse(void) {
    static const char label[] = "darwin_test_task_policy_refused\n";
    (void)write(STDERR_FILENO, label, sizeof(label) - 1);
    _exit(73);
}

static int priority(int which) {
    errno = 0;
    int value = getpriority(which, 0);
    if (errno != 0) refuse();
    return value;
}

static void get_policy(int flavor, integer_t *values, mach_msg_type_number_t expected) {
    mach_msg_type_number_t count = expected;
    boolean_t defaults = FALSE;
    if (task_policy_get(mach_task_self(), flavor, values, &count, &defaults) != KERN_SUCCESS ||
        count != expected) refuse();
}

static struct facts observe(void) {
    struct facts out = {0};
    task_category_policy_data_t category = {0};
    struct task_qos_policy qos = {0};
    get_policy(TASK_CATEGORY_POLICY, (integer_t *)&category, TASK_CATEGORY_POLICY_COUNT);
    get_policy(TASK_OVERRIDE_QOS_POLICY, (integer_t *)&qos, TASK_QOS_POLICY_COUNT);
    out.background = priority(PRIO_DARWIN_PROCESS);
    out.nice = priority(PRIO_PROCESS);
    out.role = category.role;
    out.latency = qos.task_latency_qos_tier;
    out.throughput = qos.task_throughput_qos_tier;
    out.qos = (int)qos_class_self();
    return out;
}

static void set_latency(const struct facts *prior, int tier) {
    struct task_qos_policy requested = {
        .task_latency_qos_tier = tier,
        .task_throughput_qos_tier = prior->throughput,
    };
    if (task_policy_set(mach_task_self(), TASK_OVERRIDE_QOS_POLICY,
                        (task_policy_t)&requested, TASK_QOS_POLICY_COUNT) != KERN_SUCCESS)
        refuse();
}

static void same_other_facts(const struct facts *before, const struct facts *after) {
    if (before->background != after->background || before->nice != after->nice ||
        before->role != after->role || before->throughput != after->throughput) refuse();
}

static int proof_fd(void) {
    const char *raw = getenv("AEGIS_DARWIN_POLICY_PROOF_FD");
    if (!raw || !*raw) refuse();
    char *end = NULL;
    errno = 0;
    long value = strtol(raw, &end, 10);
    if (errno || *end || value < 3 || value > 1024) refuse();
    return (int)value;
}

__attribute__((constructor)) static void task_policy_witness(void) {
    const char *mode = getenv("AEGIS_DARWIN_POLICY_MODE");
    const char *expected = getenv("AEGIS_DARWIN_POLICY_EXE");
    const char *injected = getenv("DYLD_INSERT_LIBRARIES");
    const char *selftest = getenv("AEGIS_DARWIN_POLICY_DLOPEN_SELFTEST");
    const char *library = getenv("AEGIS_DARWIN_POLICY_LIB");
    const char *nonce = getenv("AEGIS_DARWIN_POLICY_NONCE");
    char executable[PATH_MAX] = {0};
    uint32_t capacity = sizeof(executable);
    if (!mode || !expected || !library || !nonce || strlen(nonce) != 32 ||
        _NSGetExecutablePath(executable, &capacity) != 0 ||
        strcmp(executable, expected) != 0) refuse();
    for (int index = 0; index < 32; ++index)
        if (!((nonce[index] >= '0' && nonce[index] <= '9') ||
              (nonce[index] >= 'a' && nonce[index] <= 'f'))) refuse();
    char nonce_copy[33];
    memcpy(nonce_copy, nonce, sizeof(nonce_copy));
    int kind = -1;
    if (strcmp(mode, "observe") == 0) kind = 0;
    if (strcmp(mode, "normalize") == 0) kind = 1;
    if (strcmp(mode, "selftest_seed3") == 0) kind = 2;
    if (strcmp(mode, "selftest_seed3_normalize") == 0) kind = 3;
    if (strcmp(mode, "selftest_utility") == 0) kind = 4;
    if (strcmp(mode, "selftest_utility_normalize") == 0) kind = 5;
    if (kind < 0) refuse();
    if (kind >= 2) {
        if (!selftest || strcmp(selftest, "1") != 0 || injected) refuse();
    } else if (selftest || !injected || strcmp(injected, library) != 0) refuse();
    int fd = proof_fd();
    struct facts before = observe(), seeded = before, after = before;
    if (kind == 2 || kind == 3) {
        /* The dummy seeded this in main before dlopen, after its own exec. */
        if (before.latency != LATENCY_QOS_TIER_3) refuse();
    }
    if (kind >= 4 && (before.latency != LATENCY_QOS_TIER_0 ||
                      before.qos != QOS_CLASS_UTILITY)) refuse();
    if (kind == 1 || kind == 3 || kind == 5) {
        /* Normalize the final main thread; child policy is measured separately. */
        if (pthread_set_qos_class_self_np(QOS_CLASS_DEFAULT, 0) != 0) refuse();
        set_latency(kind == 3 ? &seeded : &before, LATENCY_QOS_TIER_0);
        after = observe();
        same_other_facts(&before, &after);
        if (after.latency != LATENCY_QOS_TIER_0 || after.qos != QOS_CLASS_DEFAULT) refuse();
    } else {
        after = observe();
        same_other_facts(&before, &after);
        if (after.latency != (kind == 2 ? LATENCY_QOS_TIER_3 : before.latency) ||
            before.qos != after.qos) refuse();
    }
    /* The test child must not inherit injection or control variables. */
    if (unsetenv("DYLD_INSERT_LIBRARIES") != 0 ||
        unsetenv("AEGIS_DARWIN_POLICY_MODE") != 0 ||
        unsetenv("AEGIS_DARWIN_POLICY_EXE") != 0 ||
        unsetenv("AEGIS_DARWIN_POLICY_LIB") != 0 ||
        unsetenv("AEGIS_DARWIN_POLICY_NONCE") != 0 ||
        unsetenv("AEGIS_DARWIN_POLICY_DLOPEN_SELFTEST") != 0 ||
        unsetenv("AEGIS_DARWIN_POLICY_PROOF_FD") != 0) refuse();
    char proof[512];
    int size = snprintf(proof, sizeof(proof),
        "{\"schema\":\"aegis_darwin_task_policy_ctor_v1\",\"pid\":%ld,\"mode\":%d,\"nonce\":\"%s\","
        "\"before_latency\":%d,\"seeded_latency\":%d,\"after_latency\":%d,"
        "\"before_throughput\":%d,\"after_throughput\":%d,"
        "\"before_bg\":%d,\"after_bg\":%d,\"before_nice\":%d,\"after_nice\":%d,"
        "\"before_role\":%d,\"after_role\":%d,\"before_qos\":%d,\"after_qos\":%d}\n",
        (long)getpid(), kind, nonce_copy, before.latency, seeded.latency, after.latency,
        before.throughput, after.throughput, before.background, after.background,
        before.nice, after.nice, before.role, after.role, before.qos, after.qos);
    if (size <= 0 || (size_t)size >= sizeof(proof) || write(fd, proof, (size_t)size) != size)
        refuse();
    close(fd);
}
