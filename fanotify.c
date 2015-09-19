/* Copyright 2015 Mark Haines
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>

char const USAGE[] =
    "Usage: fanotify [FLAGS PATH]... [FLAGS]\n"
    "Watch a directory or filesytem using fanotify\n\n"
    "If no path is supplied then watch the current directory\n\n"
    "Examples:\n"
    "   fanotify CLOSE_WRITE\n"
    "       Watch the current directory\n"
    "   fanotify CLOSE_WRITE MOUNT\n"
    "       Watch the current filesytem\n"
    "   fanotify CLOSE_WRITE \"\" /home\n"
    "       Watch the /home directory\n";

struct flag {
    uint64_t mask;
    const char * name;
};

static unsigned const MASK_COUNT = 8;

static struct flag const MASKS[8] = {
    {FAN_OPEN, "OPEN"},
    {FAN_ACCESS, "ACCESS"},
    {FAN_MODIFY, "MODIFY"},
    {FAN_CLOSE, "CLOSE"},
    {FAN_CLOSE_WRITE, "CLOSE_WRITE"},
    {FAN_CLOSE_NOWRITE, "CLOSE_NOWRITE"},
    {FAN_ONDIR, "ONDIR"},
    {FAN_EVENT_ON_CHILD, "EVENT_ON_CHILD"},
};

static const unsigned int FLAG_COUNT = 4;

static struct flag const FLAGS[4] = {
    {FAN_MARK_DONT_FOLLOW, "DONT_FOLLOW"},
    {FAN_MARK_ONLYDIR, "ONLYDIR"},
    {FAN_MARK_MOUNT, "MOUNT"},
    {FAN_MARK_IGNORED_MASK, "IGNORE"},
};


char PROC_SELF_FD[32] = "/proc/self/fd/";
char INPUT_BUFFER[4096];
char OUTPUT_BUFFER[4096];


uint64_t parse_flags(
    struct flag const * flags, unsigned flag_count, char const * pos
) {
    uint64_t mask = 0;
    unsigned j;
    char const * next = pos;
    while (*next) {
        /* Scan through the ',' separated list of flags */
        next = strchr(pos, ',');
        if (!next) { next = pos + strlen(pos); }
        for (j = 0; j < flag_count; ++j) {
            if ((strlen(flags[j].name) == (next - pos))
                    && (strncmp(flags[j].name, pos, next - pos) == 0)) {
                /* If the flag has a name we know then add it to the mask */
                mask |= flags[j].mask;
                break;
            }
        }
        if (j == flag_count) {
            /* If we don't know what the flag is then exit */
            write(2, OUTPUT_BUFFER, snprintf(
                OUTPUT_BUFFER, sizeof(OUTPUT_BUFFER),
                "Unknown value: \"%*s\"\nPossible values are:\n",
                (int)(next - pos), pos
            ));
            for (j = 0; j < flag_count; ++j) {
                write(2, OUTPUT_BUFFER, snprintf(
                    OUTPUT_BUFFER, sizeof(OUTPUT_BUFFER),
                    "    %s\n", flags[j].name
                ));
            }
            exit(1);
        }
        pos = next + 1;
    }
    return mask;
}

char * print_flags(
    char * output, char * output_end,
    struct flag const * flags, unsigned flag_count, uint64_t mask
) {
    unsigned j;
    /* If the mask is empty then we don't print anything. */
    if (!mask) return output;
    for (j = 0; j < flag_count; ++j) {
        if ((flags[j].mask & mask) == flags[j].mask ) {
            /* Print the name of the bits */
            size_t length = strlen(flags[j].name);
            if (output_end - output < length) length = output_end - output;
            memcpy(output, flags[j].name, length);
            output += length;
            if (output != output_end) { *(output++) = '|'; }
            /* Remove the bits from the mask. */
            mask &= ~flags[j].mask;
        }
    }
    if (mask) {
        /* The mask contained some bits we don't know about. Print it as hex */
        output += snprintf(
            output, output_end - output, "0x%llx", (long long) mask
        );
    } else {
        /* We have written a trailing '|' character since the mask is set and
         * we known what all the bits mean. So we can safely move output one
         * character back to remove the trailing '|' */
        --output;
    }
    return output;
}


int main(int argc, char const * argv[]) {
    int fanfd, i, result, cwdfd;
    if (argc == 1) {
        write(2, USAGE, sizeof(USAGE) - 1); exit(1);
    }
    /* Create a fanotify_fd. We only need to be notified about events, and
     * we only want to read the files. */
    fanfd = fanotify_init(FAN_CLASS_NOTIF, O_RDONLY);
    if (fanfd < 0) {
        perror("fanotify_init");
        /* The most likely reason to fail here is that we don't have
         * the CAP_SYS_ADMIN cabability needed by fanotify_init */
        if (errno == EPERM) {
            write(2, OUTPUT_BUFFER, snprintf(
                OUTPUT_BUFFER, sizeof(OUTPUT_BUFFER),
                "fanotify needs to be run as root\n"
            ));
        }
        exit(1);
    }
    /* In theory fanotify_mark should be able to take AT_FDCWD for the dirfd.
     * However it seems to complain if we pass AT_FDCWD to it. So instead we
     * open the current working directory and pass the resulting fd. */
    cwdfd = openat(AT_FDCWD, ".", O_RDONLY | O_DIRECTORY);
    if (cwdfd < 0) { perror("open"); exit(1); }
    for(i = 1; i < argc; ++i) {
        /* Parse the mask bits from the first argument */
        uint64_t mask = parse_flags(MASKS, MASK_COUNT, argv[i]);
        unsigned int flags = FAN_MARK_ADD;
        char const * path = ".";
        /* Then parse the flags bits from the second argument */
        if ((++i) < argc) flags |= parse_flags(FLAGS, FLAG_COUNT, argv[i]);
        /* Then optionally set path using the third argument */
        if ((++i) < argc) path = argv[i];
        result = fanotify_mark(fanfd, flags, mask, cwdfd, path);
        if (result < 0) { perror("fanotify_mark"); exit(1); }
    }
    close(cwdfd);

    for (;;) {
        ssize_t count = read(fanfd, INPUT_BUFFER, sizeof(INPUT_BUFFER));
        if (count < 0) { perror("read"); exit(1); }
        char * input = INPUT_BUFFER;
        char * input_end = input + count;
        struct fanotify_event_metadata * event;
        while (input != input_end) {
            char * output = OUTPUT_BUFFER;
            /* Leave space at the end of the output buffer for a '\n' */
            char * output_end = output + sizeof(OUTPUT_BUFFER) - 1;
            unsigned j;
            /* Check that we have enough input read an event structure. */
            if (input_end - input < sizeof(struct fanotify_event_metadata)) {
                perror("Invalid fanotify_event_meta"); exit(1);
            }
            event = (struct fanotify_event_metadata *) input;
            /* Check that we have all of the event structure and that it's
             * a version that we understand */
            if (input_end - input < event->event_len ||
                event->vers != FANOTIFY_METADATA_VERSION) {
                perror("Invalid fanotify_event_meta"); exit(1);
            }
            /* Print the event mask. Each bit will be separated by '|'
             * characters. */
            output = print_flags(
                output, output_end, MASKS, MASK_COUNT, event->mask
            );
            /* Print the pid of the process that this is event is from */
            output += snprintf(
                output, output_end - output, " %d ", event->pid
            );
            /* We aren't told the path of the event directly. But we can read
             * the /proc/self/fd/%d symlink to see what path the file
             * descriptor was opened with */
            snprintf(
                PROC_SELF_FD, sizeof(PROC_SELF_FD),
                "/proc/self/fd/%d", event->fd
            );
            count = readlink(PROC_SELF_FD, output, output_end - output);
            if (count < 0) { perror("readlink"); exit(1); }
            output += count;
            /* Add a newline to the end. This is always safe because we left
             * ourselves a byte of space when picking output_end */
            *(output++) = '\n';
            write(1, OUTPUT_BUFFER, output - OUTPUT_BUFFER);
            /* Close the event's file descriptor. */
            close(event->fd);
            /* Advance to the next event in the input buffer */
            input += event->event_len;
        }
    }
}
