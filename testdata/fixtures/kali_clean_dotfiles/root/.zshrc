# ~/.zshrc file for zsh interactive shells.
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
fi

if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
    PROMPT='%F{red}%n@%m%f:%F{blue}%~%f$ '
else
    PROMPT='%n@%m:%~$ '
fi
