use std::{
    fs::File,
    io::{BufReader, BufWriter, Result},
    path::PathBuf,
};

pub fn create_file_reader(file_path: &PathBuf) -> Result<BufReader<File>> {
    Ok(BufReader::new(File::open(file_path)?))
}

pub fn create_file_writer(file_path: &PathBuf) -> Result<BufWriter<File>> {
    Ok(BufWriter::new(File::create(file_path)?))
}
