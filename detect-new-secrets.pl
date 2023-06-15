#!/usr/bin/env perl

use File::Basename;
use Cwd 'abs_path';
use File::Temp qw/ tempfile tempdir /;

our ($all_secrets_file_handle, $all_secrets_file)=tempfile();
our ($new_secrets_file_handle, $new_secrets_file)=tempfile();
our ($command_to_update_baseline_file_handle, $command_to_update_baseline_file)=tempfile();

unless ($ENV{'GITHUB_ACTION_PATH'}) {
    $ENV{'GITHUB_ACTION_PATH'} = abs_path(dirname(basename($0)));
}
my $GITHUB_STEP_SUMMARY = $ENV{'GITHUB_STEP_SUMMARY'} || '/dev/stderr';

sub fetch_flags_from_file {
    my ($flag_to_add, $file_to_check) = @_;

    my @flags;
    open my $file, '<', $file_to_check;
    for my $line (<$file>) {
        chomp $line;
        if (($line =~ /\S/) && ($line !~ /^#/)) {
            push @flags, "$flag_to_add $line";
        }
    }
    close $file;

    return @flags;
}

sub scan_new_secrets {
    our ($all_secrets_file_handle, $all_secrets_file, $new_secrets_file_handle);

    my @excluded_files=fetch_flags_from_file('--exclude-files', $ENV{'EXCLUDE_FILES_PATH'});
    my @excluded_secrets=fetch_flags_from_file('--exclude-secrets', $ENV{'EXCLUDE_SECRETS_PATH'});
    my @excluded_lines=fetch_flags_from_file('--exclude-lines', $ENV{'EXCLUDE_LINES_PATH'});
    my @detect_secret_args=(@excluded_files, @excluded_secrets, @excluded_lines, $ENV{'DETECT_SECRET_ADDITIONAL_ARGS'});
    print "Running detect-secrets with args: ".join(' ', @detect_secret_args)."\n";
    push @detect_secret_args, '--baseline', $ENV{'BASELINE_FILE'};

    #system('detect-secrets', 'scan', @detect_secret_args);
    open(my $detect_secrets_handle, '-|', 'detect-secrets', 'scan', @detect_secret_args);
    while(<$detect_secrets_handle>) {
        print "... $_";
    }
    close $detect_secrets_handle;
    print $all_secrets_file_handle `detect-secrets audit '$ENV{'BASELINE_FILE'}' --report --json`;
    close $all_secrets_file_handle;

    #system('jq', 'map(select(.category == "UNVERIFIED"))', $all_secrets_file); #> "$new_secrets_file"
    open(my $jq_handle, '-|', 'jq', 'map(select(.category == "UNVERIFIED"))', $all_secrets_file);
    while(<$jq_handle>) {
        print $new_secrets_file_handle "$_";
    }
    close $jq_handle;
    close $new_secrets_file_handle;
}

sub advice_if_none_are_secret_short {
    my $jobs_summary_link="$ENV{'GITHUB_SERVER_URL'}/$ENV{'GITHUB_REPOSITORY'}/actions/runs/$ENV{'GITHUB_RUN_ID'}/attempts/$ENV{'GITHUB_RUN_ATTEMPT'}";

    return qq<
### If none of these are secrets or you don't care about these secrets
1. Visit →→→"$jobs_summary_link"
2. Run the command under \`Command to Update Secrets Baseline\`
3. Push the generated commit to GitHub
>;

}

sub generate_command_to_update_secrets_baseline {
    our $command_to_update_baseline_file_handle;

    my $contents = `jq 'setpath(["results"]; (.results | map_values(. | map_values(setpath(["is_secret"]; (.is_secret // false))))))' "$ENV{'BASELINE_FILE'}"`;
    print $command_to_update_baseline_file_handle qq#
cat << 'NEW_BASELINE' > '$ENV{'NEW_BASELINE'}'
$contents
NEW_BASELINE

git add '$ENV{'NEW_BASELINE'}'
git commit -m 'Updating baseline file' '$ENV{'NEW_BASELINE'}'
#;

    close $command_to_update_baseline_file_handle;
}

sub advice_if_none_are_secret_verbose {
    generate_command_to_update_secrets_baseline

    print qq{
### If none of these are secrets or you don't care about these secrets
Replace the file \`$ENV{'NEW_BASELINE'}\` with:

<details>
    <summary>Command to Update Secrets Baseline</summary>

\`\`\`sh
};
    open my $file, '<', $command_to_update_baseline_file;
        print while (<$file>);
    close $file;
    print qq{
\`\`\`
</details>
};
}

sub markdown_from_new_secrets {
    our $new_secrets_file;

    my $secrets_table_body=`jq -r '.[] | "|\(.filename)|\(.lines | keys)|\(.types)|"' "$new_secrets_file"`;
    $secrets_table_body =~ s/["\[\]]//g;

    return qq!
# Secret Scanner Report
## Potential new secrets discovered
|FILE|LINES|TYPES|
|----|-----|-----|
$secret_table_body

## What you should do
### If any of these are secrets
Secrets pushed to GitHub are not safe to use.

For the secrets you have just compromised (it is NOT sufficient to rebase to remove the commit), you should:
* Rotate the secret
!;
}

print "::add-matcher::$ENV{'GITHUB_ACTION_PATH'}/secret-problem-matcher.json\n";
unless ($ENV{'BASELINE_FILE'}) {
    my $baseline_file_handle;
    ($baseline_file_handle, $ENV{'BASELINE_FILE'})=tempfile();
    $ENV{'NEW_BASELINE'} = '.secrets.baseline';
    `jq 'del(.results[])' "$ENV{'GITHUB_ACTION_PATH'}/.secrets.baseline" > "$ENV{'BASELINE_FILE'}"`;
} else {
    $ENV{'NEW_BASELINE'} = $ENV{'BASELINE_FILE'};
}
scan_new_secrets;

my $secrets = `cat $new_secrets_file`;
if ($secrets eq '[]' ) {
    print "No new secrets found\n";
    exit 0;
}

my $markdown_limited_advice=markdown_from_new_secrets();
my $markdown_console_advice=advice_if_none_are_secret_short();

# Print a short message to the console
print "$markdown_limited_advice";
print "$markdown_console_advice";

# Write a more detailed message to the jobs summary
open my $summary, '>>', $ENV{'GITHUB_STEP_SUMMARY'};
print $summary "$markdown_limited_advice";
print $summary advice_if_none_are_secret_verbose();
close $summary;
exit 1;
