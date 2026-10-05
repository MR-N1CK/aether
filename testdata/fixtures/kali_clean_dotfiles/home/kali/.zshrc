# ~/.zshrc
if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
    PROMPT='%F{blue}%~%f$ '
fi
