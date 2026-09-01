BEGIN {
    if (expected !~ /^[0-9]+$/) {
        print "invalid expected cover count" > "/dev/stderr"
        exit 2
    }
}

$1 == "**" && $2 ~ /^[0-9]+$/ && $3 == "of" &&
$4 ~ /^[0-9]+$/ && $5 == "cover" &&
$6 == "properties" && $7 == "satisfied" {
    satisfied += $2
    required += $4
    if ($2 != $4) {
        bad = 1
    }
}

END {
    printf "satisfied=%d reported=%d expected=%d\n", satisfied, required, expected
    if (bad || satisfied != required || required != expected) {
        exit 1
    }
}
