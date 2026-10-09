// Empirical probe of the Darwin notify semantics the Apple ScreenStateObserver depends on.
//
// Question 1 (#12, initial state): does notify_register_dispatch deliver the block
//   immediately on registration, without any notify_post?
// Question 2 (#8, displayStatus): what is the state of com.apple.iokit.hid.displayStatus
//   when the display is on / off, and is "state == 1" the right reading of "on"?
//
// Run: notifyprobe <mode>
//   fresh   register a brand-new name nobody posts      -> does it fire?
//   state   set state then post, from a second token    -> does state arrive?
//   system  register the two names the observer uses    -> do they exist, what state?
#include <dispatch/dispatch.h>
#include <notify.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int fired = 0;

static void report(const char *tag, int token, uint32_t status) {
    uint64_t state = 0;
    uint32_t gs = notify_get_state(token, &state);
    printf("[%s] post=%d token=%d get_state_status=%u state=%llu\n",
           tag, fired, token, gs, (unsigned long long)state);
    fflush(stdout);
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "fresh";
    dispatch_queue_t q = dispatch_queue_create("dsh.notifyprobe", NULL);

    if (strcmp(mode, "fresh") == 0) {
        // A name nothing has ever posted or set state on.
        char name[128];
        snprintf(name, sizeof name, "com.dsh.probe.fresh.%d", (int)getpid());
        int token = -1;
        uint32_t st = notify_register_dispatch(name, &token, q, ^(int t) {
            fired++;
            report("fresh-handler", t, 0);
        });
        report("fresh-register", token, st);
        printf("[fresh] registered '%s' status=%u; waiting 2s for an unsolicited delivery\n", name, st);
        fflush(stdout);
        sleep(2);
        printf("[fresh] RESULT: handler_fired_without_post=%d\n", fired);
        return 0;
    }

    if (strcmp(mode, "state") == 0) {
        char name[128];
        snprintf(name, sizeof name, "com.dsh.probe.state.%d", (int)getpid());
        int token = -1;
        uint32_t st = notify_register_dispatch(name, &token, q, ^(int t) {
            fired++;
            report("state-handler", t, 0);
        });
        report("state-register", token, st);
        sleep(1);
        printf("[state] after registration, before any set_state/post: fired=%d\n", fired);
        fflush(stdout);
        // Drive it from a *separate* token, the way the system does.
        int other = -1;
        notify_register_check(name, &other);
        notify_set_state(other, 7);
        notify_post(name);
        sleep(1);
        report("state-after-post", token, 0);
        return 0;
    }

    if (strcmp(mode, "preexisting") == 0) {
        // THE #12 SCENARIO: the fact already exists before the observer registers.
        //
        // The setter token is deliberately KEPT ALIVE: cancelling the last client for a
        // name releases the notification and discards its state, which would make this
        // test measure the release rather than the registration.
        char name[128];
        snprintf(name, sizeof name, "com.dsh.probe.pre.%d", (int)getpid());
        int setter = -1;
        notify_register_check(name, &setter);
        notify_set_state(setter, 1);
        notify_post(name);
        uint64_t sstate = 0;
        notify_get_state(setter, &sstate);
        printf("[preexisting] setter token=%d alive, state set to 1 and posted; setter reads %llu\n",
               setter, (unsigned long long)sstate);
        fflush(stdout);

        int token = -1;
        uint32_t st = notify_register_dispatch(name, &token, q, ^(int t) {
            fired++;
            report("preexisting-handler", t, 0);
        });
        uint64_t state = 0;
        uint32_t gs = notify_get_state(token, &state);
        printf("[preexisting] dispatch registration status=%u token=%d; "
               "notify_get_state(dispatch token) status=%u reports %llu\n",
               st, token, gs, (unsigned long long)state);
        // notify_check documents that the FIRST check for a registration reports a change.
        int check = -1;
        notify_register_check(name, &check);
        int changed = 0;
        uint32_t cs = notify_check(check, &changed);
        printf("[preexisting] notify_check on a fresh registration: status=%u changed=%d\n",
               cs, (int)changed);
        printf("[preexisting] waiting 3s to see whether the pre-existing fact is delivered\n");
        fflush(stdout);
        sleep(3);
        printf("[preexisting] RESULT: handler_fired_from_preexisting_state=%d\n", fired);
        return 0;
    }

    if (strcmp(mode, "system") == 0) {
        const char *names[] = {
            "com.apple.iokit.hid.displayStatus",
            "com.apple.springboard.lockstate",
            "com.apple.springboard.lockcomplete",
            "com.apple.iokit.hid.displayStatusChanged",
        };
        for (int i = 0; i < 4; i++) {
            int token = -1;
            fired = 0;
            uint32_t st = notify_register_dispatch(names[i], &token, q, ^(int t) {
                fired++;
                report("system-handler", t, 0);
            });
            uint64_t state = 0;
            uint32_t gs = notify_get_state(token, &state);
            printf("[system] %-40s register_status=%u token=%d get_state=%u state=%llu\n",
                   names[i], st, token, gs, (unsigned long long)state);
            fflush(stdout);
            sleep(1);
            printf("[system] %-40s fired_immediately=%d\n", names[i], fired);
            fflush(stdout);
            notify_cancel(token);
        }
        return 0;
    }

    fprintf(stderr, "unknown mode %s\n", mode);
    return 2;
}
