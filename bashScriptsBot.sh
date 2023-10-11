#!/usr/bin/bash
#!/usr/bin/mail

# The above three lines of scripts, is basically telling Linux or Bash to ' hey i am #using this Command Line Interface' and the packages as well such mail to send mail to # users

# current directory path
current_dir="${PWD}"

# array of files
suspicious_files=()

# array of suspecious code in a file
suspicious_code=()

# detected changes
gitStatusChanges=()

# function would scan for malicious code or a suspicious file on project dir
# would then append them to an array variable of malicious_code or suspicious file
# and notify admin users via mail
function scan_file() {
	echo "scan file function works!"
	# the command below would find specific file on current directory
	# then it would search for patterns or regexp for each file that matches with the keyword below
	suspicious_code=$(find "${current_dir}" -type f -name '*.php' | xargs egrep -i "(mail|fsockopen|pfsockopen|stream_socket_client|exec|system|passthru|eval|base64_decode) *\(")
	# printf "${current_dir}"

	# This command would look for any file that contain x29
	# as this translate a bracket when using hex codes
	malicious_files=$(find "${current_dir}" -type f -name '*.php' | xargs grep -il x29)
	for file in $suspicious_code; do
		suspicious_code+=("$file")
	done
	printf "\n%s\n" "${suspicious_code[*]}" >"${current_dir}/"suspicious_code.txt

	for file in $malicious_files; do
		# echo $file
		suspicious_files+=("$file")
	done

	printf "\n%s\n" "${suspicious_files[*]}" >"${current_dir}"/suspicious_files.txt
}

function detect_any_recent_changes() {
	echo "git status function works!"
	gitStatus=$(git --git-dir="${current_dir}"/.git --work-tree="${current_dir}/" status -s)
	echo "$gitStatus"
	# ((${#a[@]}))
	echo " -z ${#gitStatus[@]}"
	if ((${#gitStatus[@]})); then
		for file in $gitStatus; do
			gitStatusChanges+=("$file")
		done
		echo "${gitStatusChanges[*]}"

		printf "\n%s\n " "${gitStatusChanges[*]}" >"${current_dir}"/detected_changes.txt

		scan_file
		notify_admin_via_mail
	else
		echo "No recent changes detected!"

	fi
}

# function name is self explanatory
function notify_admin_via_mail() {
	echo "notify admin via mail function works!"
	mail -s "Urgent! Check server files!" "${EMAIL}", -A "${current_dir}"/suspicious_files.txt , -A "${current_dir}"/detected_changes.txt , -A "${current_dir}"/suspicious_code.txt </dev/null
	sudo rm -rf ./detected_changes ./suspecious_files ./suspicious_code
	exit
}

detect_any_recent_changes
