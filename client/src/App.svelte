<script>
	import { onMount } from "svelte";
	let devices = null;
	onMount(async () => {
		const res = await fetch("/devices",
		{
			method: 'GET', // *GET, POST, PUT, DELETE, etc.
			mode: 'no-cors', // no-cors, *cors, same-origin
			cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
			credentials: 'same-origin', // include, *same-origin, omit
			headers: {
				'Content-Type': 'application/json'
			// 'Content-Type': 'application/x-www-form-urlencoded',
			}
		});
		devices = await res.json();
	});
	let updateDevice = (device, level) => {
		device.level = level
		fetch("/devices/" +  device.id,
			{
				method: 'PATCH',
				body:    JSON.stringify(device),
				headers: { 'Content-Type': 'application/json' }
			}
		);
		let objIndex = devices.findIndex(obj => obj.id == device.id);
		console.log("Before update: ", devices[objIndex]);
		devices[objIndex] = device;
	};
</script>
<style>
	@import url("https://fonts.googleapis.com/css?family=Nunito&display=swap");
	* {
		font-family: "Nunito", sans-serif;
	}
  .loading {
    opacity: 0;
    animation: 0.4s 0.8s forwards fade-in;
	}
	.card-header .badge { 
		position: absolute;
  	right: 6px;   /* must be equal to parent's right padding */
	}
	.btn, .btn-xs {
		padding: .25rem .4rem;
		font-size: .875rem;
		line-height: .5;
		border-radius: .2rem;
	}
</style>
<section>
	<div class="container">
		<div class="row mt-5 ">
			{#if devices}
				{#each devices as device}
					<div class="col-md-4">
						<div class="card mb-3">
							<div class="card-header">{device.owner}
								{#if device.level == -1}
									<span class="badge badge-pill badge-success">No Access</span>
								{:else if device.level == 0}
									<span class="badge badge-pill badge-info">Level 0</span>
								{:else if device.level == 1}
									<span class="badge badge-pill badge-warning">Level 1</span>
								{:else}
									<span class="badge badge-pill badge-danger">Level 2</span>
								{/if}
							</div>
							<div class="card-body">
								<h6 class="card-title">{device.device}</h6>
								<button type="submit" class="btn btn-success btn-xs" on:click|preventDefault={updateDevice(device, -1)}>
									No Access
								</button>
								<button type="submit" class="btn btn-info btn-xs" on:click|preventDefault={updateDevice(device, 0)}>
									Level 0
								</button>
								<button type="submit" class="btn btn-warning btn-xs" on:click|preventDefault={updateDevice(device, 1)}>
									Level 1
								</button>
								<button type="submit" class="btn btn-danger btn-xs" on:click|preventDefault={updateDevice(device, 2)}>
									Level 2
								</button>
							</div>
						</div>
					</div>
				{/each}
			{:else}
				<p class="loading">loading...</p>
			{/if}
		</div>
	</div>
</section>
