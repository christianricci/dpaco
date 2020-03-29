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
	let data = {
		id: null,
		owner: "",
		device: "",
		ip_address: "",
		mac_adess: "",
		level: 4
	};
	let addDevice = () => {
		const newDevice = {
			id: devices.length + 1,
			owner: data.owner,
			device: data.device,
			ip_address: data.ip_address,
			mac_address: data.mac_address,
			level: data.level
		};
		devices = devices.concat(newDevice);
		data = {
			id: null,
			owner: "",
			device: "",
			ip_address: "",
			mac_adess: "",
			level: 4
		};
		console.log(devices);
	};
	let isEdit = false;
	let editDevice = device => {
		isEdit = true;
		data = device;
	};
	let updateDevice = () => {
		isEdit = !isEdit;
		let deviceDB = {
			id: data.id,
			owner: data.owner,
			device: data.device,
			ip_address: data.ip_address,
			mac_address: data.mac_address,
			level: data.level
		};
		let objIndex = devices.findIndex(obj => obj.id == deviceDB.id);
		console.log("Before update: ", devices[objIndex]);
		devices[objIndex] = deviceDB;
		fetch("/devices/" +  deviceDB.id,
			{
				method: 'PATCH',
				body:    JSON.stringify(deviceDB),
				headers: { 'Content-Type': 'application/json' }
			}
		);
		data = {
			id: null,
			owner: "",
			device: "",
			ip_address: "",
			mac_address: "",
			level: ""
		};
	};
	let deleteDevice = id => {
		console.log(id);
		devices = devices.filter(device => device.id !== id);
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
  @keyframes fade-in {
    from { opacity: 0; }
    to { opacity: 1; }
  }
  li {
    list-style-type: georgian;
  }	
</style>
<section>
	<div class="container">
		<div class="row mt-5 ">
			<div class="col-md-6">
				<div class="card p-2 shadow">
					<div class="card-body">
						<h5 class="card-title mb-4">Add New Device</h5>
						<form>
							<div class="form-group">
								<label for="title">Owner</label>
								<input
									bind:value={data.owner}
									type="text"
									class="form-control"
									id="text"
									placeholder="device Owner" />
							</div>
							<div class="form-group">
								<label for="category">Device</label>
								<select
									class="form-control"
									id="device"
									bind:value={data.device}>
									<option selected disabled>Select a Device</option>
									<option value="Mobile">Mobile</option>
									<option value="Laptop">Laptop</option>
									<option value="Desktop">Desktop</option>
									<option value="IP-Camera">IP-Camera</option>
								</select>
							</div>
							<div class="form-group">
								<label for="content">IP Address</label>
								<input
									bind:value={data.ip_address}
									type="text"
									class="form-control"
									id="text"
									placeholder="IP Address" />
							</div>
							<div class="form-group">
								<label for="content">MAC Address</label>
								<input
									bind:value={data.mac_adess}
									type="text"
									class="form-control"
									id="text"
									placeholder="MAC Address" />
							</div>
							<div class="form-group">
								<label for="content">Access Level</label>
								<input
									bind:value={data.level}
									type="text"
									class="form-control"
									id="text"
									placeholder="Access Level" />
							</div>
							{#if isEdit === false}
								<button
									type="submit"
									on:click|preventDefault={addDevice}
									class="btn btn-primary">
									Add Device
								</button>
							{:else}
								<button
									type="submit"
									on:click|preventDefault={updateDevice}
									class="btn btn-info">
									Edit Device
								</button>
							{/if}
						</form>
					</div>
				</div>
			</div>
			<div class="col-md-6">
				{#if devices}
					{#each devices as device}
						<div class="card mb-3">
							<div class="card-header">{device.device}</div>
							<div class="card-body">
								<h5 class="card-title">{device.owner}</h5>
								<p class="card-text">{device.ip_address}</p>
								<p class="card-text">{device.mac_address}</p>
								<p class="card-text">{device.level}</p>
								<p class="card-text">{device.level}</p>
								<button class="btn btn-info" on:click={editDevice(device)}>
									Edit
								</button>
								<button class="btn btn-danger" on:click={deleteDevice(device.id)}>
									Delete
								</button>
							</div>
						</div>
					{/each}
				{:else}
					<p class="loading">loading...</p>
				{/if}
			</div>
		</div>
	</div>
</section>
