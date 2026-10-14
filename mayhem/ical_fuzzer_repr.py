#!/usr/bin/python3
# The OSS-Fuzz harness (src/icalendar/fuzzing/ical_fuzzer.py), plus repr() of every parsed calendar:
# the unmodified harness never formats a component, so it cannot reach Component.__repr__.
import base64
import contextlib
import sys

import atheris

with atheris.instrument_imports():
    import icalendar.cal.calendar
    from icalendar.tests.fuzzed import fuzz_v1_calendar


def from_ical_and_repr(calendar_string, multiple=False):
    parsed = icalendar.cal.calendar.Calendar.from_ical(calendar_string, multiple=multiple)
    for calendar in parsed if multiple else [parsed]:
        repr(calendar)
    return parsed


@atheris.instrument_func
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    multiple = fdp.ConsumeBool()
    should_walk = fdp.ConsumeBool()
    calendar_string = fdp.ConsumeString(fdp.remaining_bytes())
    print("--- start calendar ---")
    with contextlib.suppress(UnicodeEncodeError):
        print(
            base64.b64encode(calendar_string.encode("UTF-8", "surrogateescape")).decode(
                "ASCII"
            )
        )

    fuzz_v1_calendar(from_ical_and_repr, calendar_string, multiple, should_walk)
    print("--- end calendar ---")


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
