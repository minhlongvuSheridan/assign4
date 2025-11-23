using Microsoft.AspNetCore.JsonPatch;
using Microsoft.AspNetCore.Mvc;
using TaskManagement.Core.DTOs;
using TaskManagement.Core.Interfaces;
using TaskManagement.Core.Models;

namespace TaskManagement.API.Controllers
{
    public class TasksController : ControllerBase
    {
        private readonly ITaskRepository _repository;
        public TasksController(ITaskRepository repository)
        {
            _repository = repository;
        }
        // GET: api/tasks
        [HttpGet]
        public async Task<ActionResult<IEnumerable<TaskItem>>> GetAllTasks()
        {
            var tasks = await _repository.GetAllAsync();
            return Ok(tasks);
        }
        // GET: api/tasks/{id}
        [HttpGet("{id}")]
        public async Task<ActionResult<TaskItem>> GetTask(int id)
        {
            var task = await _repository.GetByIdAsync(id);
            if (task == null)
            {
                return NotFound(new { message = $"Task with ID {id} not found" });
            }
            return Ok(task);
        }
        // POST: api/tasks
        [HttpPost]
        public async Task<ActionResult<TaskItem>> CreateTask([FromBody] TaskItemCreateDto
taskDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var task = new TaskItem
            {
                Title = taskDto.Title,
                Description = taskDto.Description,
                Status = taskDto.Status,
                DueDate = taskDto.DueDate
            };

            var createdTask = await _repository.CreateAsync(task);
            return CreatedAtAction(
            nameof(GetTask),
            new { id = createdTask.Id },
            createdTask
            );
        }
        // PUT: api/tasks/{id}

        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateTask(int id, [FromBody] TaskItemUpdateDto
taskDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var exists = await _repository.ExistsAsync(id);
            if (!exists)
            {
                return NotFound(new { message = $"Task with ID {id} not found" });
            }
            var task = new TaskItem
            {
                Id = id,
                Title = taskDto.Title,
                Description = taskDto.Description,
                Status = taskDto.Status,
                DueDate = taskDto.DueDate
            };

            var updatedTask = await _repository.UpdateAsync(task);
            return Ok(updatedTask);
        }
        // PATCH: api/tasks/{id}
        [HttpPatch("{id}")]
        public async Task<IActionResult> PatchTask(int id, [FromBody]
JsonPatchDocument<TaskItem> patchDoc)
        {
            if (patchDoc == null)
            {
                return BadRequest(new { message = "Patch document is null" });
            }
            var task = await _repository.GetByIdAsync(id);
            if (task == null)
            {
                return NotFound(new { message = $"Task with ID {id} not found" });
            }
            patchDoc.ApplyTo(task, ModelState);
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            task.UpdatedAt = DateTime.UtcNow;
            await _repository.UpdateAsync(task);
            return Ok(task);
        }

    }
}
