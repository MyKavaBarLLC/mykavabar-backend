use crate::{error::Error, generic::Expirable, models::session::Session};
use std::{
	future::Future,
	pin::Pin,
	sync::{Arc, Mutex},
	thread,
};
use tokio::runtime::Runtime;

pub struct Job {
	function: Arc<Mutex<JobFunction>>,
	interval: u64,
}

impl Job {
	fn active_jobs() -> Vec<Job> {
		vec![Job::new(
			Session::clear_expired,
			60 * 60 * 24 * 7, // 1 week
		)]
	}

	fn new<F, Fut>(function: F, interval: u64) -> Self
	where
		F: Fn() -> Fut + Send + Sync + 'static,
		Fut: Future<Output = Result<(), Error>> + Send + 'static,
	{
		let function = JobFunction::new(function);

		Self { function, interval }
	}

	fn spawn(&self) {
		let i = self.interval;
		let func = Arc::clone(&self.function);

		thread::spawn(move || {
			let rt = Runtime::new().unwrap();
			rt.block_on(async move {
				loop {
					tokio::time::sleep(std::time::Duration::from_secs(i)).await;
					let cloned_func = {
						let func = func.lock().unwrap();
						func.clone()
					};
					cloned_func.call().await;
				}
			});
		});
	}

	pub fn spawn_all() {
		for job in Self::active_jobs() {
			job.spawn();
		}
	}
}

pub struct JobFunction {
	func: Arc<dyn Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>,
}

impl Clone for JobFunction {
	fn clone(&self) -> Self {
		Self {
			func: self.func.clone(),
		}
	}
}

impl JobFunction {
	pub fn new<F, Fut>(function: F) -> Arc<Mutex<Self>>
	where
		F: Fn() -> Fut + Send + Sync + 'static,
		Fut: Future<Output = Result<(), Error>> + Send + 'static,
	{
		let s = Self {
			func: Arc::new(move || {
				let future = function();

				Box::pin(async move {
					if let Err(e) = future.await {
						log::error!("Job function error: {}", e);
					}
				})
			}),
		};

		Arc::new(Mutex::new(s))
	}

	pub fn call(&self) -> Pin<Box<dyn Future<Output = ()> + Send>> {
		(self.func)()
	}
}
