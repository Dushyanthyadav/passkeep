use clap::{Arg, ArgMatches, Command, command};
use std::io;
use std::process;

pub fn build_cli() -> Command {
    command!()
        .about("A simple password manager")
        .arg(
            Arg::new("Add")
                .short('a')
                .long("add")
                .help("Add account")
                .action(clap::ArgAction::SetTrue)
                .exclusive(true),
        )
        .arg(
            Arg::new("Show")
                .short('s')
                .long("show")
                .help("Shows a specific Account details")
                .action(clap::ArgAction::SetTrue)
                .exclusive(true),
        )
        .arg(
            Arg::new("Show-All")
                .short('l')
                .long("show-all")
                .action(clap::ArgAction::SetTrue)
                .help("Shows all Account deails")
                .exclusive(true),
        )
        .arg(
            Arg::new("Remove")
                .short('r')
                .long("remove")
                .help("removes a specific Account details")
                .action(clap::ArgAction::SetTrue)
                .exclusive(true),
        )
        .arg(
            Arg::new("Remove-All")
                .short('d')
                .long("remove-all")
                .help("Deletes all Accounts")
                .action(clap::ArgAction::SetTrue)
                .exclusive(true),
        )
        .arg(
            Arg::new("Change-MasterPassword")
                .short('c')
                .long("change-masterpassword")
                .help("change the master password")
                .action(clap::ArgAction::SetTrue)
                .exclusive(true),
        )
}

pub fn parse() -> ArgMatches {
    let match_results = build_cli().get_matches();

    match match_results.args_present() {
        true => match_results,
        false => {
            build_cli().print_help().unwrap();
            process::exit(0);
        }
    }
}

pub fn prompt(message: &str) -> String {
    print!("{}", message);

    io::Write::flush(&mut io::stdout()).expect("flush failed");

    let mut string = String::new();
    std::io::stdin()
        .read_line(&mut string)
        .expect("Error while parsing the code");
    let string = string.trim().to_string();

    string
}
